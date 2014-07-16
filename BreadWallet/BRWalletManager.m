//
//  BRWalletManager.m
//  BreadWallet
//
//  Created by Aaron Voisine on 3/2/14.
//  Copyright (c) 2014 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRWalletManager.h"
#import "BRWallet.h"
#import "BRKey.h"
#import "BRKey+BIP38.h"
#import "BRKeySequence.h"
#import "BRBIP39Mnemonic.h"
#import "BRPeer.h"
#import "BRTransaction.h"
#import "BRTransactionEntity.h"
#import "BRAddressEntity.h"
#import "NSString+Base58.h"
#import "NSMutableData+Bitcoin.h"
#import "NSManagedObject+Sugar.h"
#import "Reachability.h"

#define BTC         @"\xE1\x97\x90" 			// capital V with a stroke through middle (utf-8)
#define BITS        @"\x6D" + @"\xE1\x97\x90"   // mV (utf-8)
#define NARROW_NBSP @"\xE2\x80\xAF" 			// narrow no-break space (utf-8)

#define LOCAL_CURRENCY_SYMBOL_KEY @"LOCAL_CURRENCY_SYMBOL"
#define LOCAL_CURRENCY_CODE_KEY   @"LOCAL_CURRENCY_CODE"
#define LOCAL_CURRENCY_PRICE_KEY  @"LOCAL_CURRENCY_PRICE"
#define PIN_KEY                   @"pin"
#define PIN_FAIL_COUNT_KEY        @"pinfailcount"
#define PIN_FAIL_HEIGHT_KEY       @"pinfailheight"
#define MNEMONIC_KEY              @"mnemonic"
#define SEED_KEY                  @"seed"
#define CREATION_TIME_KEY         @"creationtime"

#define SEED_ENTROPY_LENGTH     (128/8)
#define SEC_ATTR_SERVICE        @"com.sovereignshare.vertlet"
#define DEFAULT_CURRENCY_PRICE  1.0
#define DEFAULT_CURRENCY_CODE   @"USD"
#define DEFAULT_CURRENCY_SYMBOL @"$"

#define BASE_URL    @"https://blockchain.info"
#define UNSPENT_URL BASE_URL "/unspent?active="
#define TICKER_URL  BASE_URL "/ticker"
#define VTC_BTC_TICKER_URL @"http://pubapi.cryptsy.com/api.php?method=singlemarketdata&marketid=151"

static BOOL setKeychainData(NSData *data, NSString *key)
{
    if (! key) return NO;

    NSDictionary *query = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService:SEC_ATTR_SERVICE,
                            (__bridge id)kSecAttrAccount:key,
                            (__bridge id)kSecReturnData:(id)kCFBooleanTrue};

    SecItemDelete((__bridge CFDictionaryRef)query);

    if (! data) return YES;

    NSDictionary *item = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecAttrService:SEC_ATTR_SERVICE,
                           (__bridge id)kSecAttrAccount:key,
                           (__bridge id)kSecAttrAccessible:(__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                           (__bridge id)kSecValueData:data};
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);

    if (status != noErr) {
        NSLog(@"SecItemAdd error status %d", (int)status);
        return NO;
    }

    return YES;
}

static NSData *getKeychainData(NSString *key)
{
    NSDictionary *query = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService:SEC_ATTR_SERVICE,
                            (__bridge id)kSecAttrAccount:key,
                            (__bridge id)kSecReturnData:(id)kCFBooleanTrue};
    CFDataRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);

    if (status != noErr) {
        NSLog(@"SecItemCopyMatching error status %d", (int)status);
        return nil;
    }

    return CFBridgingRelease(result);
}

@interface BRWalletManager()

@property (nonatomic, strong) BRWallet *wallet;
@property (nonatomic, strong) Reachability *reachability;
@property (nonatomic, assign) BOOL sweepFee;
@property (nonatomic, strong) NSString *sweepKey;
@property (nonatomic, strong) void (^sweepCompletion)(BRTransaction *tx, NSError *error);

@end

@implementation BRWalletManager

+ (instancetype)sharedInstance
{
    static id singleton = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        singleton = [self new];
    });

    return singleton;
}

- (instancetype)init
{
    if (! (self = [super init])) return nil;

    [NSManagedObject setConcurrencyType:NSPrivateQueueConcurrencyType];

    self.reachability = [Reachability reachabilityForInternetConnection];

    self.format = [NSNumberFormatter new];
    self.format.lenient = YES;
    self.format.numberStyle = NSNumberFormatterCurrencyStyle;
    self.format.minimumFractionDigits = 0;
    self.format.negativeFormat = [self.format.positiveFormat
                                  stringByReplacingCharactersInRange:[self.format.positiveFormat rangeOfString:@"#"]
                                  withString:@"-#"];
    //self.format.currencySymbol = BITS NARROW_NBSP;
    //self.format.maximumFractionDigits = 2;
    //self.format.maximum = @21000000000000.0;
    self.format.currencySymbol = BTC NARROW_NBSP;
    self.format.maximumFractionDigits = 8;
    self.format.maximum = @21000000.0;

    [self updateExchangeRate];

    return self;
}

- (void)dealloc
{
    [NSObject cancelPreviousPerformRequestsWithTarget:self];
}

- (BRWallet *)wallet
{
    if (_wallet == nil && self.seed) {
        @synchronized(self) {
            if (_wallet == nil) {
                _wallet = [[BRWallet alloc] initWithContext:[NSManagedObject context]
                           andSeed:^NSData *{ return self.seed; }];
            }
        }
    }

    return _wallet;
}

- (NSData *)seed
{
    return getKeychainData(SEED_KEY);
}

- (void)setSeed:(NSData *)seed
{
    @autoreleasepool { // @autoreleasepool ensures sensitive data will be dealocated immediately
        if ([seed isEqual:self.seed]) return;

        [[NSManagedObject context] performBlockAndWait:^{
            [BRAddressEntity deleteObjects:[BRAddressEntity allObjects]];
            [BRTransactionEntity deleteObjects:[BRTransactionEntity allObjects]];
            [NSManagedObject saveContext];
        }];

        setKeychainData(nil, PIN_KEY);
        setKeychainData(nil, PIN_FAIL_COUNT_KEY);
        setKeychainData(nil, PIN_FAIL_HEIGHT_KEY);
        setKeychainData(nil, MNEMONIC_KEY);
        setKeychainData(nil, CREATION_TIME_KEY);
        if (! setKeychainData(seed, SEED_KEY)) {
            NSLog(@"error setting wallet seed");
            [[[UIAlertView alloc] initWithTitle:@"couldn't create wallet"
              message:@"error adding master private key to iOS keychain, make sure app has keychain entitlements"
              delegate:self cancelButtonTitle:@"abort" otherButtonTitles:nil] show];
            return;
        }

        _wallet = nil;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:BRWalletManagerSeedChangedNotification object:nil];
    });
}

- (NSString *)seedPhrase
{
    @autoreleasepool {
        NSData *phrase = getKeychainData(MNEMONIC_KEY);

        if (! phrase) return nil;

        return CFBridgingRelease(CFStringCreateFromExternalRepresentation(SecureAllocator(), (CFDataRef)phrase,
                                                                          kCFStringEncodingUTF8));
    }
}

- (void)setSeedPhrase:(NSString *)seedPhrase
{
    @autoreleasepool {
        BRBIP39Mnemonic *m = [BRBIP39Mnemonic sharedInstance];
        
        seedPhrase = [m encodePhrase:[m decodePhrase:seedPhrase]];
        self.seed = [m deriveKeyFromPhrase:seedPhrase withPassphrase:nil];

        NSData *d = CFBridgingRelease(CFStringCreateExternalRepresentation(SecureAllocator(), (CFStringRef)seedPhrase,
                                                                           kCFStringEncodingUTF8, 0));
        
        setKeychainData(d, MNEMONIC_KEY);
    }
}

- (NSString *)pin
{
    @autoreleasepool {
        NSData *pin = getKeychainData(PIN_KEY);

        if (! pin) return nil;

        return CFBridgingRelease(CFStringCreateFromExternalRepresentation(SecureAllocator(), (CFDataRef)pin,
                                                                          kCFStringEncodingUTF8));
    }
}

- (void)setPin:(NSString *)pin
{
    @autoreleasepool {
        if (pin.length > 0) {
            NSData *d = CFBridgingRelease(CFStringCreateExternalRepresentation(SecureAllocator(), (CFStringRef)pin,
                                                                               kCFStringEncodingUTF8, 0));

            setKeychainData(d, PIN_KEY);
        }
        else setKeychainData(nil, PIN_KEY);
    }
}

- (NSUInteger)pinFailCount
{
        NSData *count = getKeychainData(PIN_FAIL_COUNT_KEY);

        return (count.length < sizeof(NSUInteger)) ? 0 : *(const NSUInteger *)count.bytes;
}

- (void)setPinFailCount:(NSUInteger)count
{
    if (count > 0) {
        NSMutableData *d = [NSMutableData secureDataWithLength:sizeof(NSUInteger)];

        *(NSUInteger *)d.mutableBytes = count;
        setKeychainData(d, PIN_FAIL_COUNT_KEY);
    }
    else setKeychainData(nil, PIN_FAIL_COUNT_KEY);
}

- (uint32_t)pinFailHeight
{
    NSData *height = getKeychainData(PIN_FAIL_HEIGHT_KEY);

    return (height.length < sizeof(uint32_t)) ? 0 : *(const uint32_t *)height.bytes;
}

- (void)setPinFailHeight:(uint32_t)height
{
    if (height > 0) {
        NSMutableData *d = [NSMutableData secureDataWithLength:sizeof(uint32_t)];

        *(uint32_t *)d.mutableBytes = height;
        setKeychainData(d, PIN_FAIL_HEIGHT_KEY);
    }
    else setKeychainData(nil, PIN_FAIL_HEIGHT_KEY);
}

- (void)generateRandomSeed
{
    @autoreleasepool {
        NSMutableData *entropy = [NSMutableData secureDataWithLength:SEED_ENTROPY_LENGTH];
        NSTimeInterval time = [NSDate timeIntervalSinceReferenceDate];

        SecRandomCopyBytes(kSecRandomDefault, entropy.length, entropy.mutableBytes);

        self.seedPhrase = [[BRBIP39Mnemonic sharedInstance] encodePhrase:entropy];

        // we store the wallet creation time on the keychain because keychain data persists even when an app is deleted
        setKeychainData([NSData dataWithBytes:&time length:sizeof(time)], CREATION_TIME_KEY);
    }
}

- (NSTimeInterval)seedCreationTime
{
    NSData *d = getKeychainData(CREATION_TIME_KEY);

    return (d.length < sizeof(NSTimeInterval)) ? BITCOIN_REFERENCE_BLOCK_TIME : *(const NSTimeInterval *)d.bytes;
}

- (void)updateExchangeRate
{
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(updateExchangeRate) object:nil];
    [self performSelector:@selector(updateExchangeRate) withObject:nil afterDelay:60.0];

    if (self.reachability.currentReachabilityStatus == NotReachable) return;
    
    NSURLRequest *vtcBtcReq = [NSURLRequest requestWithURL:[NSURL URLWithString:VTC_BTC_TICKER_URL]
                                            cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10.0];
    
    [NSURLConnection sendAsynchronousRequest:vtcBtcReq queue:[NSOperationQueue currentQueue]
    completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
        if (connectionError) {
            NSLog(@"%@", connectionError);
            return;
        }
        
        NSError *error = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        
        if (error
            || ! [json isKindOfClass:[NSDictionary class]]
            || ! [json[@"return"] isKindOfClass:[NSDictionary class]]
            || ! [json[@"return"][@"markets"] isKindOfClass:[NSDictionary class]]
            || ! [json[@"return"][@"markets"][@"VTC"] isKindOfClass:[NSDictionary class]]
            //|| ! [json[@"return"][@"markets"][@"VTC"][@"lasttradeprice"] isKindOfClass:[NSNumber class]]
            ) {
                NSLog(@"unexpected response from pubapi.cryptsy.com:\n%@",
                      [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
                return;
            }
        
        NSNumber *vtcBtcValue = json[@"return"][@"markets"][@"VTC"][@"lasttradeprice"];
        
        NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:TICKER_URL]
                                             cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10.0];
        
        [NSURLConnection sendAsynchronousRequest:req queue:[NSOperationQueue currentQueue]
                               completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
                                   if (connectionError) {
                                       NSLog(@"%@", connectionError);
                                       return;
                                   }
                                   
                                   NSError *error = nil;
                                   NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
                                   NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
                                   NSString *currencyCode = [[NSLocale currentLocale] objectForKey:NSLocaleCurrencyCode];
                                   NSString *symbol = [[NSLocale currentLocale] objectForKey:NSLocaleCurrencySymbol];
                                   
                                   if (error || ! [json isKindOfClass:[NSDictionary class]] ||
                                       ! [json[DEFAULT_CURRENCY_CODE] isKindOfClass:[NSDictionary class]] ||
                                       ! [json[DEFAULT_CURRENCY_CODE][@"last"] isKindOfClass:[NSNumber class]] ||
                                       ([json[currencyCode] isKindOfClass:[NSDictionary class]] &&
                                        ! [json[currencyCode][@"last"] isKindOfClass:[NSNumber class]])) {
                                           NSLog(@"unexpected response from blockchain.info:\n%@",
                                                 [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
                                           return;
                                       }
                                   
                                   if (! [json[currencyCode] isKindOfClass:[NSDictionary class]]) { // if local currency is missing, use default
                                       currencyCode = DEFAULT_CURRENCY_CODE;
                                       symbol = DEFAULT_CURRENCY_SYMBOL;
                                   }
                                   
                                   [defs setObject:symbol forKey:LOCAL_CURRENCY_SYMBOL_KEY];
                                   [defs setObject:currencyCode forKey:LOCAL_CURRENCY_CODE_KEY];
                                   
                                   NSNumber *lastPrice = json[currencyCode][@"last"];
                                   
                                   [defs setObject:[NSNumber numberWithFloat:(lastPrice.floatValue * vtcBtcValue.floatValue)] forKey:LOCAL_CURRENCY_PRICE_KEY];
                                   [defs synchronize];
                                   NSLog(@"exchange rate updated to %@/%@", [self localCurrencyStringForAmount:SATOSHIS],
                                         [self stringForAmount:SATOSHIS]);
                                   
                                   if (! self.wallet) return;
                                   
                                   dispatch_async(dispatch_get_main_queue(), ^{
                                       [[NSNotificationCenter defaultCenter] postNotificationName:BRWalletBalanceChangedNotification object:nil];
                                   });
                               }];
    }];
}

// given a private key, queries blockchain for unspent outputs and calls the completion block with a signed transaction
// that will sweep the balance into the wallet (doesn't publish the tx)
- (void)sweepPrivateKey:(NSString *)privKey withFee:(BOOL)fee
completion:(void (^)(BRTransaction *tx, NSError *error))completion
{
    if (! completion) return;

    if ([privKey isValidBitcoinBIP38Key]) {
        UIAlertView *v = [[UIAlertView alloc] initWithTitle:@"password protected key" message:nil delegate:self
                          cancelButtonTitle:@"cancel" otherButtonTitles:@"ok", nil];

        v.alertViewStyle = UIAlertViewStyleSecureTextInput;
        [v textFieldAtIndex:0].returnKeyType = UIReturnKeyDone;
        [v textFieldAtIndex:0].placeholder = @"password";
        [v show];

        self.sweepKey = privKey;
        self.sweepFee = fee;
        self.sweepCompletion = completion;
        return;
    }

    NSString *address = [[BRKey keyWithPrivateKey:privKey] address];

    if (! address) {
        completion(nil, [NSError errorWithDomain:@"Vertlet" code:187 userInfo:@{NSLocalizedDescriptionKey:
                         NSLocalizedString(@"not a valid private key", nil)}]);
        return;
    }

    if ([self.wallet containsAddress:address]) {
        completion(nil, [NSError errorWithDomain:@"Vertlet" code:187 userInfo:@{NSLocalizedDescriptionKey:
                         NSLocalizedString(@"this private key is already in your wallet", nil)}]);
        return;
    }

    NSURL *u = [NSURL URLWithString:[UNSPENT_URL stringByAppendingString:address]];
    NSURLRequest *req = [NSURLRequest requestWithURL:u cachePolicy:NSURLRequestReloadIgnoringCacheData
                         timeoutInterval:20.0];

    [NSURLConnection sendAsynchronousRequest:req queue:[NSOperationQueue currentQueue]
    completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
        if (connectionError) {
            completion(nil, connectionError);
            return;
        }

        NSError *error = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        uint64_t balance = 0, standardFee = 0;
        BRTransaction *tx = [BRTransaction new];

        if (error) {
            if ([[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] hasPrefix:@"No free outputs"]) {
                error = [NSError errorWithDomain:@"Vertlet" code:417 userInfo:@{NSLocalizedDescriptionKey:
                         NSLocalizedString(@"this private key is empty", nil)}];
            }

            completion(nil, error);
            return;
        }

        if (! [json isKindOfClass:[NSDictionary class]] ||
            ! [json[@"unspent_outputs"] isKindOfClass:[NSArray class]]) {
            completion(nil, [NSError errorWithDomain:@"Vertlet" code:417 userInfo:@{NSLocalizedDescriptionKey:
                             [NSString stringWithFormat:NSLocalizedString(@"unexpected response from %@", nil), u.host]
                            }]);
            return;
        }

        //TODO: make sure not to create a transaction larger than TX_MAX_SIZE
        for (NSDictionary *utxo in json[@"unspent_outputs"]) {
            if (! [utxo isKindOfClass:[NSDictionary class]] ||
                ! [utxo[@"tx_hash"] isKindOfClass:[NSString class]] || ! [utxo[@"tx_hash"] hexToData] ||
                ! [utxo[@"tx_output_n"] isKindOfClass:[NSNumber class]] ||
                ! [utxo[@"script"] isKindOfClass:[NSString class]] || ! [utxo[@"script"] hexToData] ||
                ! [utxo[@"value"] isKindOfClass:[NSNumber class]]) {
                completion(nil, [NSError errorWithDomain:@"Vertlet" code:417 userInfo:@{NSLocalizedDescriptionKey:
                                 [NSString stringWithFormat:NSLocalizedString(@"unexpected response from %@", nil),
                                  u.host]}]);
                return;
            }

            [tx addInputHash:[utxo[@"tx_hash"] hexToData] index:[utxo[@"tx_output_n"] unsignedIntegerValue]
             script:[utxo[@"script"] hexToData]];
            balance += [utxo[@"value"] unsignedLongLongValue];
        }

        if (balance == 0) {
            completion(nil, [NSError errorWithDomain:@"Vertlet" code:417 userInfo:@{NSLocalizedDescriptionKey:
                             NSLocalizedString(@"this private key is empty", nil)}]);
            return;
        }

        // we will be adding a wallet output (additional 34 bytes)
        //TODO: calculate the median of the lowest fee-per-kb that made it into the previous 144 blocks (24hrs)
        if (fee) standardFee = ((tx.size + 34 + 999)/1000)*TX_FEE_PER_KB;

        if (standardFee + TX_MIN_OUTPUT_AMOUNT > balance) {
            completion(nil, [NSError errorWithDomain:@"Vertlet" code:417 userInfo:@{NSLocalizedDescriptionKey:
                             NSLocalizedString(@"transaction fees would cost more than the funds available on this "
                                               "private key (due to tiny \"dust\" deposits)",nil)}]);
            return;
        }

        [tx addOutputAddress:[self.wallet changeAddress] amount:balance - standardFee];

        if (! [tx signWithPrivateKeys:@[privKey]]) {
            completion(nil, [NSError errorWithDomain:@"Vertlet" code:401 userInfo:@{NSLocalizedDescriptionKey:
                             NSLocalizedString(@"error signing transaction", nil)}]);
            return;
        }

        completion(tx, nil);
    }];
}

#pragma mark - string helpers

// TODO: make this work with local currency amounts
- (int64_t)amountForString:(NSString *)string
{
    return ([[self.format numberFromString:string] doubleValue] + DBL_EPSILON)*
           pow(10.0, self.format.maximumFractionDigits);
}

- (NSString *)stringForAmount:(int64_t)amount
{
    NSUInteger min = self.format.minimumFractionDigits;

    if (amount == 0) {
        self.format.minimumFractionDigits =
            self.format.maximumFractionDigits > 4 ? 4 : self.format.maximumFractionDigits;
    }

    NSString *r = [self.format stringFromNumber:@(amount/pow(10.0, self.format.maximumFractionDigits))];

    self.format.minimumFractionDigits = min;

    return r;
}

- (NSString *)localCurrencyStringForAmount:(int64_t)amount
{
    static NSNumberFormatter *format = nil;

    if (! format) {
        format = [NSNumberFormatter new];
        format.lenient = YES;
        format.numberStyle = NSNumberFormatterCurrencyStyle;
        format.negativeFormat = [format.positiveFormat
                                 stringByReplacingCharactersInRange:[format.positiveFormat rangeOfString:@"#"]
                                 withString:@"-#"];
    }

    if (amount == 0) return [format stringFromNumber:@(0)];

    NSString *symbol = [[NSUserDefaults standardUserDefaults] stringForKey:LOCAL_CURRENCY_SYMBOL_KEY];
    NSString *code = [[NSUserDefaults standardUserDefaults] stringForKey:LOCAL_CURRENCY_CODE_KEY];
    double price = [[NSUserDefaults standardUserDefaults] doubleForKey:LOCAL_CURRENCY_PRICE_KEY];

    if (! symbol.length || price <= DBL_EPSILON) {
        return [format stringFromNumber:@(DEFAULT_CURRENCY_PRICE*amount/SATOSHIS)];
    }

    format.currencySymbol = symbol;
    format.currencyCode = code;

    NSString *ret = [format stringFromNumber:@(price*amount/SATOSHIS)];

    // if the amount is too small to be represented in local currency (but is != 0) then return a string like "<$0.01"
    if (amount > 0 && price*amount/SATOSHIS + DBL_EPSILON < 1.0/pow(10.0, format.maximumFractionDigits)) {
        ret = [@"<" stringByAppendingString:[format stringFromNumber:@(1.0/pow(10.0, format.maximumFractionDigits))]];
    }
    else if (amount < 0 && price*amount/SATOSHIS - DBL_EPSILON > -1.0/pow(10.0, format.maximumFractionDigits)) {
        // technically should be '>', but '<' is more intuitive
        ret = [@"<" stringByAppendingString:[format stringFromNumber:@(-1.0/pow(10.0, format.maximumFractionDigits))]];
    }

    return ret;
}

#pragma mark - UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    if (buttonIndex == alertView.cancelButtonIndex) {
        if ([[alertView buttonTitleAtIndex:buttonIndex] isEqual:@"abort"]) abort();

        if (self.sweepCompletion) self.sweepCompletion(nil, nil);
        self.sweepKey = nil;
        self.sweepCompletion = nil;
        return;
    }

    if (! self.sweepKey || ! self.sweepCompletion) return;

    NSString *passphrase = [[alertView textFieldAtIndex:0] text];

    dispatch_async(dispatch_get_main_queue(), ^{
        BRKey *key = [BRKey keyWithBIP38Key:self.sweepKey andPassphrase:passphrase];

        if (! key) {
            UIAlertView *v = [[UIAlertView alloc] initWithTitle:@"password protected key"
                              message:@"bad password, try again" delegate:self cancelButtonTitle:@"cancel"
                              otherButtonTitles:@"ok", nil];

            v.alertViewStyle = UIAlertViewStyleSecureTextInput;
            [v textFieldAtIndex:0].returnKeyType = UIReturnKeyDone;
            [v textFieldAtIndex:0].placeholder = @"password";
            [v show];
        }
        else {
            [self sweepPrivateKey:key.privateKey withFee:self.sweepFee completion:self.sweepCompletion];
            self.sweepKey = nil;
            self.sweepCompletion = nil;
        }
    });
}

@end
