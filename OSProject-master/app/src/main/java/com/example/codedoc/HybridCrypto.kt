import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import java.io.*
import java.security.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class HybridCrypto(private val context: Context) {

    // Генерация ключей
    fun generateRSAKeyPair(keySize: Int = 2048): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(keySize)
        return keyGen.generateKeyPair()
    }

    private fun generateAESKey(keySize: Int = 256): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(keySize)
        return keyGen.generateKey()
    }

    // Шифрование
    fun encryptFileWithRSA(
        inputUri: Uri,
        outputUri: Uri,
        encryptedKeyUri: Uri,
        publicKey: PublicKey
    ) {
        val contentResolver = context.contentResolver

        // Генерируем ключи
        val aesKey = generateAESKey()
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }

        // Шифруем AES ключ RSA
        val rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedAesKey = rsaCipher.doFinal(aesKey.encoded)

        // Сохраняем зашифрованный ключ
        contentResolver.openOutputStream(encryptedKeyUri)?.use {
            it.write(encryptedAesKey)
        } ?: throw IOException("Не могу сохранить ключ")

        // Шифруем файл AES
        val aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, IvParameterSpec(iv))

        contentResolver.openInputStream(inputUri)?.use { input ->
            contentResolver.openOutputStream(outputUri)?.use { output ->
                // Записываем IV в начало файла
                output.write(iv)

                // Шифруем данные
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    output.write(aesCipher.update(buffer, 0, bytesRead))
                }
                output.write(aesCipher.doFinal())
            } ?: throw IOException("Cannot open file output stream")
        } ?: throw IOException("Cannot open file input stream")
    }

    // Расшифровка
    fun decryptFileWithRSA(
        encryptedUri: Uri,
        decryptedUri: Uri,
        encryptedKeyUri: Uri,
        privateKey: PrivateKey
    ) {
        val contentResolver = context.contentResolver

        // Читаем зашифрованный AES ключ
        val encryptedAesKey = contentResolver.openInputStream(encryptedKeyUri)?.use {
            it.readBytes()
        } ?: throw IOException("Не могу прочесть зашифрованный ключ")

        // Расшифровываем AES ключ
        val rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
        val aesKeyBytes = rsaCipher.doFinal(encryptedAesKey)
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")

        // Читаем и расшифровываем файл
        contentResolver.openInputStream(encryptedUri)?.use { input ->
            contentResolver.openOutputStream(decryptedUri)?.use { output ->
                // Читаем IV из начала файла
                val iv = ByteArray(16).also { input.read(it) }

                // Инициализируем AES для расшифровки
                val aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey, IvParameterSpec(iv))

                // Расшифровываем данные
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    output.write(aesCipher.update(buffer, 0, bytesRead))
                }
                output.write(aesCipher.doFinal())
            } ?: throw IOException("Cannot open decrypted file output")
        } ?: throw IOException("Cannot open encrypted file input")
    }
}