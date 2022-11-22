import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        vigenereCipher2TimePadAttack();
        rsaDictionaryAttack();
    }

    private static void rsaDictionaryAttack() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        RSACipher rc = new RSACipher();
        String cipherText = "1724628E8F984818533128131AB66DCD4B2ADAA816873FABEAB92BB8B38D4C8BAEADAAF1CAFF9FFDAEA24AC9196B9472168EF6892CEDCED85505ECBC711059DE";
        byte[] cipherBytes = new BigInteger(cipherText,16).toByteArray(); //convert to byte array so can compare to rsaEncrypt output
        System.out.println("cipherBytes (hex): "+ new BigInteger(cipherBytes).toString(16).toUpperCase());

        BufferedReader in = new BufferedReader(new FileReader("src/english.txt"));

        String word;
        while ((word = in.readLine()) != null) {
            byte[] data = word.getBytes(); //convert to byte array so can be used by RSACipher
            byte[] wordCipherbytes;
            wordCipherbytes = rc.rsaEncrypt(data); //encrypt each word using RSA encryption
            if (Arrays.equals(cipherBytes, wordCipherbytes)){ //if ciphertext match plaintext must match so word found
                System.out.println("wordCipherbytes (hex): "+ new BigInteger(wordCipherbytes).toString(16).toUpperCase());
                System.out.println("matching word: " + word);
            }
        }
    }

    private static void vigenereCipher2TimePadAttack() throws IOException {
        BufferedReader in = new BufferedReader(new FileReader("src/10letterwordslist.txt"));
        String str;

        List<String> tenLetterWords = new ArrayList<String>();

        while ((str = in.readLine()) != null) {
            tenLetterWords.add(str);
        }

        for (String word : tenLetterWords) {
            for (String wordToCompare : tenLetterWords) {
                boolean match =
                        Math.floorMod((int) word.charAt(0) - (int) wordToCompare.charAt(0),26) == 15 &&
                        Math.floorMod((int) word.charAt(1) - (int) wordToCompare.charAt(1),26) == 0 &&
                        Math.floorMod((int) word.charAt(2) - (int) wordToCompare.charAt(2),26) == 6 &&
                        Math.floorMod((int) word.charAt(3) - (int) wordToCompare.charAt(3),26) == 5 &&
                        Math.floorMod((int) word.charAt(4) - (int) wordToCompare.charAt(4),26) == 15 &&
                        Math.floorMod((int) word.charAt(5) - (int) wordToCompare.charAt(5),26) == 17 &&
                        Math.floorMod((int) word.charAt(6) - (int) wordToCompare.charAt(6),26) == 21 &&
                        Math.floorMod((int) word.charAt(7) - (int) wordToCompare.charAt(7),26) == 9 &&
                        Math.floorMod((int) word.charAt(8) - (int) wordToCompare.charAt(8),26) == 13 &&
                        Math.floorMod((int) word.charAt(9) - (int) wordToCompare.charAt(9),26) == 8;
                if (match) {
                    System.out.println(word + ", " + wordToCompare);
                }
            }
        }
    }
}