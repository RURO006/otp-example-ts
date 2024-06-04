export type AlgorithmName = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * This is an example implementation of the OATH
 * OTP algorithm.
 * Visit www.openauthentication.org for more information.
 * @author Johan Rydell, PortWise, Inc.
 */
export class TOTP {
    private static DIGITS_POWER =
        // 0 1  2   3    4     5      6       7        8
        [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

    /**
     * HMAC SHA加密
     * @param algorithmName 加密演算法，預設SHA-512
     * @param keyBuffer 加密key
     * @param dataBuffer 資料
     * @returns 加密後結果
     */
    public static async HMAC_SHA(
        algorithmName: AlgorithmName = 'SHA-512',
        keyBuffer: Uint8Array | ArrayBuffer,
        dataBuffer: Uint8Array | ArrayBuffer
    ): Promise<{
        hash: ArrayBuffer;
        toHex: () => string[];
    }> {
        const key = await window.crypto.subtle.importKey(
            'raw',
            new Uint8Array(keyBuffer),
            { name: 'HMAC', hash: algorithmName },
            false,
            ['sign']
        );
        let hash = await window.crypto.subtle.sign('HMAC', key, dataBuffer);
        return {
            hash,
            toHex: () => {
                const out = new Uint8Array(hash);
                return Array.from(out).map((i) => i.toString(16).padStart(2, '0').toUpperCase());
            },
        };
    }

    /**
     * This method generates a TOTP value for the given set of parameters.
     * @param key the shared secret
     * @param time a value that reflects a time
     * @param returnDigits number of digits to return
     * @param crypto the crypto function to use
     * @returns a numeric string in base 10 that includes {@link truncationDigits} digits
     */
    public static async generateTOTP(
        key: ArrayBuffer | Uint8Array,
        time: bigint,
        returnDigits: number,
        crypto: AlgorithmName
    ): Promise<string> {
        const codeDigits = returnDigits;
        const dv = new DataView(new ArrayBuffer(8), 0);
        dv.setBigUint64(0, time);
        const timeBytes = new Uint8Array(dv.buffer);
        const hmacResult = await TOTP.HMAC_SHA(crypto, key, timeBytes);
        const hash = new Uint8Array(hmacResult.hash);

        const offset = hash[hash.length - 1] & 0xf;
        const binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);
        const otp = binary % TOTP.DIGITS_POWER[codeDigits];
        return otp.toString().padStart(codeDigits, '0');
    }

    /**
     * 測試
     */
    public static async Test() {
        const regex = /\w{2}/g;
        // Seed for HMAC-SHA1 - 20 bytes
        const seed = new Uint8Array('3132333435363738393031323334353637383930'.match(regex)!.map((o) => +('0x' + o)));
        // Seed for HMAC-SHA256 - 32 bytes
        const seed32 = new Uint8Array(
            ('3132333435363738393031323334353637383930' + '313233343536373839303132')
                .match(regex)!
                .map((o) => +('0x' + o))
        );
        // Seed for HMAC-SHA512 - 64 bytes
        const seed64 = new Uint8Array(
            (
                '3132333435363738393031323334353637383930' +
                '3132333435363738393031323334353637383930' +
                '3132333435363738393031323334353637383930' +
                '31323334'
            )
                .match(regex)!
                .map((o) => +('0x' + o))
        );

        const T0 = 0n;
        const X = 30n;
        const testTime = [59n, 1111111109n, 1111111111n, 1234567890n, 2000000000n, 20000000000n];

        for (let i = 0; i < testTime.length; i++) {
            const T = (testTime[i] - T0) / X;
            const steps = T;
            const fmtTime = testTime[i].toString().padStart(11, ' ');
            const utcTime = new Date(Number(testTime[i] * 1000n));
            console.debug(
                `|  ${fmtTime}  |  ${utcTime.toISOString()}  | ${steps.toString(16)} |${await TOTP.generateTOTP(
                    seed,
                    steps,
                    8,
                    'SHA-1'
                )}| SHA1   |`
            );
            console.debug(
                `|  ${fmtTime}  |  ${utcTime.toISOString()}  | ${steps.toString(16)} |${await TOTP.generateTOTP(
                    seed32,
                    steps,
                    8,
                    'SHA-256'
                )}| SHA256 |`
            );
            console.debug(
                `|  ${fmtTime}  |  ${utcTime.toISOString()}  | ${steps.toString(16)} |${await TOTP.generateTOTP(
                    seed64,
                    steps,
                    8,
                    'SHA-512'
                )}| SHA512 |`
            );
            console.debug('+---------------+-----------------------+' + '------------------+--------+--------+');
        }
    }
}
