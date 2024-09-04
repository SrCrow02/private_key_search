import * as secp256k1 from 'secp256k1';
import BN from 'bn.js';

class KeyFinder {
    private static readonly G = Buffer.from('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex');
    private static readonly ORDER = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

    private static calculatePublicKeyPoint(targetPublicKeyHex: string): Buffer {
        // Remove prefix '0x' if present
        const cleanHex = targetPublicKeyHex.startsWith('0x') ? targetPublicKeyHex.slice(2) : targetPublicKeyHex;
        return Buffer.from(cleanHex, 'hex');
    }

    private static bsgs(targetPoint: Buffer, maxSteps: BN, start: BN): [BN | null, number] {
        const babySteps = new Map<string, number>();
        let stepsTried = 0;

        // Baby-step
        let current = Buffer.from(secp256k1.publicKeyCreate(start.toArrayLike(Buffer, 'be', 32), false));
        for (let i = 0; i < maxSteps.toNumber(); i++) {
            babySteps.set(current.toString('hex'), i);
            current = Buffer.from(secp256k1.publicKeyCombine([current, this.G]));
            stepsTried++;
        }

        // Giant-step
        let giant = secp256k1.publicKeyTweakMul(this.G, maxSteps.toArrayLike(Buffer, 'be', 32));
        let currentPoint = Buffer.from(targetPoint);
        for (let j = 0; j < maxSteps.toNumber(); j++) {
            const currentHex = currentPoint.toString('hex');
            if (babySteps.has(currentHex)) {
                const i = babySteps.get(currentHex)!;
                return [start.add(new BN(j).mul(maxSteps)).add(new BN(i)), stepsTried];
            }
            currentPoint = Buffer.from(secp256k1.publicKeyCombine([currentPoint, giant]));
            stepsTried++;
        }

        return [null, stepsTried];
    }

    public static findPrivateKey(startRangeHex: string, endRangeHex: string, targetPublicKeyHex: string): BN | null {
        const startRange = new BN(startRangeHex, 16);
        const endRange = new BN(endRangeHex, 16);
        const intervalSize = endRange.sub(startRange).add(new BN(1));
        const maxSteps = new BN(2).pow(new BN(Math.floor(Math.log2(Math.sqrt(intervalSize.toNumber())))));
        const targetPublicKeyPoint = KeyFinder.calculatePublicKeyPoint(targetPublicKeyHex);

        for (let start = startRange; start.lt(endRange); start = start.add(maxSteps)) {
            const [key, steps] = KeyFinder.bsgs(targetPublicKeyPoint, maxSteps, start);
            if (key !== null) {
                return key;
            }
            console.log(`[+] ${start.toString(16)} - ${start.add(maxSteps).lt(endRange) ? start.add(maxSteps).toString(16) : endRange.toString(16)}`);
        }

        return null;
    }
}

export { KeyFinder }