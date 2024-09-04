import * as secp256k1 from 'secp256k1';
import BN from 'bn.js';

class KeyFinder {
    private static readonly G = Buffer.from('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex');
    private static readonly ORDER = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

    private static calculatePublicKeyPoint(targetPublicKeyHex: string): Buffer {
        const cleanHex = targetPublicKeyHex.startsWith('0x') ? targetPublicKeyHex.slice(2) : targetPublicKeyHex;
        return Buffer.from(cleanHex, 'hex');
    }

    private static bsgs(targetPoint: Buffer, maxSteps: BN, start: BN): [BN | null, BN] {
        const babySteps = new Map<string, BN>();
        let stepsTried = new BN(0);

        // Baby-step
        let current = Buffer.from(secp256k1.publicKeyCreate(start.toArrayLike(Buffer, 'be', 32), false));
        for (let i = new BN(0); i.lt(maxSteps); i = i.add(new BN(1))) {
            babySteps.set(current.toString('hex'), i);
            current = Buffer.from(secp256k1.publicKeyCombine([current, this.G]));
            stepsTried = stepsTried.add(new BN(1));
        }

        // Giant-step
        let giant = secp256k1.publicKeyTweakMul(this.G, maxSteps.toArrayLike(Buffer, 'be', 32));
        let currentPoint = Buffer.from(targetPoint);
        for (let j = new BN(0); j.lt(maxSteps); j = j.add(new BN(1))) {
            const currentHex = currentPoint.toString('hex');
            if (babySteps.has(currentHex)) {
                const i = babySteps.get(currentHex)!;
                return [start.add(j.mul(maxSteps)).add(i), stepsTried];
            }
            currentPoint = Buffer.from(secp256k1.publicKeyCombine([currentPoint, giant]));
            stepsTried = stepsTried.add(new BN(1));
        }

        return [null, stepsTried];
    }

    private static sqrt(num: BN): BN {
        if (num.lte(new BN(1))) {
            return num;
        }

        let x = num.div(new BN(2));
        let y = num.div(x);

        while (x.gt(y)) {
            x = y;
            y = num.div(x).add(x).div(new BN(2));
        }

        return x;
    }

    public static findPrivateKey(startRangeHex: string, endRangeHex: string, targetPublicKeyHex: string, blockSize?: BN): BN | null {
        const startRange = new BN(startRangeHex, 16);
        const endRange = new BN(endRangeHex, 16);
        const intervalSize = endRange.sub(startRange).add(new BN(1));
        const sqrtIntervalSize = this.sqrt(intervalSize);
        const defaultBlockSize = new BN(2).pow(new BN(sqrtIntervalSize.bitLength() - 1));
        const maxSteps = blockSize || defaultBlockSize;
        const targetPublicKeyPoint = KeyFinder.calculatePublicKeyPoint(targetPublicKeyHex);

        let totalSteps = new BN(0);
        let startTime = Date.now();
        let lastReportTime = startTime;

        for (let start = startRange; start.lt(endRange); start = start.add(maxSteps)) {
            const [key, steps] = KeyFinder.bsgs(targetPublicKeyPoint, maxSteps, start);
            totalSteps = totalSteps.add(steps);

            if (key !== null) {
                const endTime = Date.now();
                const totalTime = (endTime - startTime) / 1000; // em segundos
                console.log(`Chave privada encontrada: ${key.toString(16)}`);
                console.log(`Tempo total: ${totalTime.toFixed(2)} segundos`);
                console.log(`Total de tentativas: ${totalSteps.toString()}`);
                return key;
            }

            if (totalSteps.gte(new BN(1000000))) {
                const currentTime = Date.now();
                const elapsedTime = (currentTime - lastReportTime) / 1000; // em segundos
                console.log(`[+] ${start.toString(16)} - ${start.add(maxSteps).lt(endRange) ? start.add(maxSteps).toString(16) : endRange.toString(16)}`);
                console.log(`Tempo desde último relatório: ${elapsedTime.toFixed(2)} segundos`);
                console.log(`Tentativas desde último relatório: ${totalSteps.toString()}`);
                totalSteps = new BN(0);
                lastReportTime = currentTime;
            }
        }

        console.log("Chave privada não encontrada.");
        return null;
    }

    public static searchInBlocks(startRangeHex: string, endRangeHex: string, targetPublicKeyHex: string, blockSize: BN): BN | null {
        const startRange = new BN(startRangeHex, 16);
        const endRange = new BN(endRangeHex, 16);

        for (let blockStart = startRange; blockStart.lt(endRange); blockStart = blockStart.add(blockSize)) {
            const blockEnd = BN.min(blockStart.add(blockSize), endRange);
            console.log(`Procurando no bloco: ${blockStart.toString(16)} - ${blockEnd.toString(16)}`);
            
            const result = this.findPrivateKey(blockStart.toString(16), blockEnd.toString(16), targetPublicKeyHex, blockSize);
            if (result !== null) {
                return result;
            }
        }

        return null;
    }
}

export { KeyFinder }