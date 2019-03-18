import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

//creates an attack on two plaintext messages in hex format encrypted with the same key using one-time pad encryption
//works on single words of found in wordlist.txt, prints all possible combinations
public class otp_attack {
    private static final String c1 = "4A5C45492449552A";
    private static final String c2 = "5A47534D35525F20";
    private static final String path = "wordlist.txt";

    public static HashSet<String> readWordLibrary() throws IOException {
        //all possible words in a hashset for a quick lookup
        HashSet<String> strings = new HashSet<>();
        strings.addAll(Files.readAllLines(Paths.get(path)));
        return strings;
    }

    public static byte[] XOR(byte[] byte1, byte[] byte2){
        //we assume byte1 and byte2 are of same length
        byte[] byteXOR = new byte[byte1.length];
        for(int i = 0; i < byte1.length; i++)
            byteXOR[i] = (byte) (byte1[i] ^ byte2[i]);
        return byteXOR;
    }

    public static void main(String[] args) throws IOException {
        //c1 XOR c2 equals m1 XOR m2
        byte[] c1XORc2 = XOR(DatatypeConverter.parseHexBinary(c1), DatatypeConverter.parseHexBinary(c2));
        HashSet<String> library = readWordLibrary();
        List<String[]> results = new ArrayList<>();

        for(String word: library){
            byte[] m1 = word.getBytes();
            if(m1.length == c1XORc2.length) {
                byte[] m2 = XOR(c1XORc2, m1); //c1 XOR c2 XOR m1 equals m2
                if(library.contains(new String(m2)))
                    results.add(new String[]{new String(m1), new String(m2)});
            }
        }

        for (String[] res: results)
            System.out.println(res[0] + ", " + res[1]);
    }
}