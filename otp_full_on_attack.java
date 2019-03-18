import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

//converts two strings to a single XORed byte array, giving the same result if they had been encrypted with a same key before
//then searches for word combinations found in wordlist.txt, separated by spaces, that would match
public class otp_full_on_attack {
    private static final String path = "wordlist.txt";
    private static final String m1 = "i am here";
    private static final String m2 = "cat yawns";

    private static byte[] c1XORc2gen() {
        String m1hex = String.format("%x", new BigInteger(1, m1.getBytes(StandardCharsets.UTF_8)));
        String m2hex = String.format("%x", new BigInteger(1, m2.getBytes(StandardCharsets.UTF_8)));
        if(m1hex.length() != m2hex.length())
            throw new Error("Bad lengths");
        return XOR(DatatypeConverter.parseHexBinary(m1hex), DatatypeConverter.parseHexBinary(m2hex));
    }

    //already in byte[] format, used for XORing
    private static List<byte[]> readWords() throws IOException {
        List<String> rawStrings = Files.readAllLines(Paths.get(path));
        List<byte[]> strings = new ArrayList<>();
        for(String s: rawStrings)
            strings.add(s.getBytes(StandardCharsets.UTF_8));
        return strings;
    }

    //used for searches
    private static HashSet<String> readWordLibrary() throws IOException {
        return new HashSet<>(Files.readAllLines(Paths.get(path)));
    }

    private static byte[] XOR(byte[] byte1, byte[] byte2){
        //we assume byte1 and byte2 are of same length
        byte[] byteXOR = new byte[byte1.length];
        for(int i = 0; i < byte1.length; i++) byteXOR[i] = (byte) (byte1[i] ^ byte2[i]);
        return byteXOR;
    }

    public static void main(String[] args) throws IOException {
        long start = System.currentTimeMillis();

        byte[] c1XORc2 = c1XORc2gen();
        List<byte[]> words = readWords();
        HashSet<String> library = readWordLibrary();

        Decryptor decryptor = new Decryptor(words, library, c1XORc2);
        decryptor.sentenceDecrypt();
        decryptor.displayResults();

        long stop = System.currentTimeMillis();
        System.out.println((stop - start) + "ms");
    }
}

class Decryptor{
    public List<byte[]> words;
    public HashSet<String> library;
    public List<String[]> results;
    private byte[] c1XORc2;
    private byte[] spaceBytes = " ".getBytes();
    private ByteArrayOutputStream out;

    public Decryptor(List<byte[]> words, HashSet<String> library, byte[] c1XORc2) {
        this.words = words;
        this.library = library;
        this.c1XORc2 = c1XORc2;
        out = new ByteArrayOutputStream();
    }

    public void sentenceDecrypt() throws IOException{
        results = new ArrayList<>();
        for(int i = 0; i < words.size(); i++){
            byte[] m1 = words.get(i);

            if(m1.length < c1XORc2.length) {
                if(i % 250 == 0) System.out.println(i + "/100411"); //random progress display
                byte[] m2 = shortXOR(c1XORc2, m1, m1.length);
                if(checkm2(m2, false))
                    sentenceDecrypt(m1);
            }
            //complete sentence filled, if all fits, then added to results
            else if(m1.length == c1XORc2.length) {
                byte[] m2 = XOR(c1XORc2, m1);
                if(checkm2(m2,true))
                    results.add(new String[]{new String(m1), new String(m2)});
            }
        }
    }

    public void sentenceDecrypt(byte[] prev)throws IOException{
        for (byte[] word : words) {
            //word + space + word has to fit
            if (prev.length + 1 + word.length < c1XORc2.length) {
                out.write(prev);
                out.write(spaceBytes);
                out.write(word);
                byte[] m1 = out.toByteArray();
                out.reset();

                byte[] m2 = shortXOR(c1XORc2, m1, m1.length);
                if (checkm2(m2, false)) {
                    sentenceDecrypt(m1);
                }
            }
            //complete sentence filled, if all fits then added to results
            else if (prev.length + 1 + word.length == c1XORc2.length) {
                out.write(prev);
                out.write(spaceBytes);
                out.write(word);
                byte[] m1 = out.toByteArray();
                out.reset();

                byte[] m2 = XOR(c1XORc2, m1);
                if (checkm2(m2, true))
                    results.add(new String[]{new String(m1), new String(m2)});
            }
        }
    }

    private static byte[] XOR(byte[] byte1, byte[] byte2){
        //we assume byte1 and byte2 are of same length
        byte[] byteXOR = new byte[byte1.length];
        for(int i = 0; i < byte1.length; i++)
            byteXOR[i] = (byte) (byte1[i] ^ byte2[i]);
        return byteXOR;
    }

    private static byte[] shortXOR(byte[] byte1, byte[] byte2, int len){
        //we assume len <= byte1.length, byte2.length
        byte[] byteXOR = new byte[len];
        for(int i = 0; i < len; i++)
            byteXOR[i] = (byte) (byte1[i] ^ byte2[i]);
        return byteXOR;
    }

    //to remove results which do not match even before being completed
    private boolean checkm2(byte[] m2, boolean last){
        String m2Str = new String(m2);
        //last: whether the whole string has to fit the regex parameters
        if(last) {
            if (!m2Str.matches("([\\p{javaAlphabetic}']+(\\s))*[\\p{javaAlphabetic}']+"))
                return false;
            String[] m2StrParts = m2Str.split(" ");
            for(int i = 0; i < m2StrParts.length; i++){
                if(!library.contains(m2StrParts[i]))
                    return false;
            }
            return true;
        }
        else {
            if(!m2Str.matches("([\\p{javaAlphabetic}']+(\\s))*[\\p{javaAlphabetic}']+(\\s)?"))
                return false;
            String[] m2StrParts = m2Str.split(" ");
            //not checking the last one
            for(int i = 0; i < m2StrParts.length - 1; i++){
                if(!library.contains(m2StrParts[i]))
                    return false;
            }
            return true;
        }
    }

    public void displayResults(){
        for (String[] res: results)
            System.out.println(res[0] + ", " + res[1]);
    }
}