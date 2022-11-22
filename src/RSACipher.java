import java.math.BigInteger;
import java.security.*;

import javax.crypto.*;

import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

public class RSACipher {

    RSAPublicKeySpec pub;
    Cipher pubCipher;

    public RSACipher() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException{
        BigInteger pubExp = new BigInteger("65537");
        BigInteger modulus= new BigInteger("8498366624123778469786221301745502847540062564446942548935813151029871109227629825128191191873256944429194363590568693176889468067716917599552841188613507");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        pub = new RSAPublicKeySpec(modulus, pubExp);

        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(pub);

        pubCipher = Cipher.getInstance("RSA/ECB/NoPadding"); //since we know original ciphertext encrypted with RSA/ECB/NoPadding
        pubCipher.init(Cipher.ENCRYPT_MODE, key);
    }
    public byte[] rsaEncrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException {
        return pubCipher.doFinal(data);
    }
}