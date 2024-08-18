const bitcoin = require('bitcoinjs-lib');
const secp256k1 = require('secp256k1');

class KeyFinder {
    findPrivateKey(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): Buffer | null {
        const startRange = BigInt(`0x${startRangeHex}`);
        const endRange = BigInt(`0x${endRangeHex}`);

        const targetPublicKey = Buffer.from(targetPublicKeyHex, 'hex');

        // Itera sobre o intervalo de chaves privadas
        for (let i = startRange; i <= endRange; i++) {
            const keyBuffer = this.bigIntToBuffer(i);
            console.log(`Tentando chave privada: ${keyBuffer.toString('hex')}`);

            if (secp256k1.privateKeyVerify(keyBuffer)) {
                const publicKey = secp256k1.publicKeyCreate(keyBuffer);

                // Compara a chave pública gerada com a chave pública alvo
                if (Buffer.compare(publicKey, targetPublicKey) === 0) {
                    console.log(`Corresponding Public Key Found: ${publicKey.toString('hex')}`);
                    return keyBuffer;
                }
            }
        }

        return null;
    }

    // Converte um BigInt em um Buffer de 32 bytes
    bigIntToBuffer(bigInt: BigInt): Buffer {
        const hex = bigInt.toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex');
    }

    // Resolve o quebra-cabeça tentando encontrar a chave privada 
    solvePuzzle(targetPublicKeyHex: string, startRangeHex: string, endRangeHex: string): void {
        console.log("Searching for private key...");

        const privateKeyBuffer = this.findPrivateKey(targetPublicKeyHex, startRangeHex, endRangeHex);

        if (privateKeyBuffer) {
            console.log(`Private key found: ${privateKeyBuffer.toString('hex')}`);
        } else {
            console.log("Private key not found in the given range");
        }
    }
}

// Função principal para executar a busca
function main() {
    const finder = new KeyFinder();

    const targetPublicKeyHex = "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852";

    // Define o intervalo máximo para busca
    const startRangeHex = "00000000000000000000000000000000000000000000000000000000000000"; // 0 em hexadecimal
    const endRangeHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // 2^256-1 em hexadecimal

    finder.solvePuzzle(targetPublicKeyHex, startRangeHex, endRangeHex);
}

main();
