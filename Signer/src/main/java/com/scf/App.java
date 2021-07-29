package com.scf;

import com.scf.SM2Sign;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;

/**
 * Hello world!
 *
 */
public class App
{
    private static final Path PROPERTIES_PATH = Paths.get("src", "main", "resources", "sm2PriKeyPkcs8.pem");

    private static String read(String fileName) throws IOException {
        URL url = App.class.getClassLoader().getResource(fileName);
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(url.getFile())));
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            int size = 0;
            byte[] temp = new byte[128];
            while ((size = bis.read(temp)) > 0) {
                outputStream.write(temp, 0, size);
            }
            return new String(outputStream.toByteArray());
        }
    }

    public static String readPriKey(String filename) throws IOException {
        String PriKeyStr = read(filename);
        PriKeyStr = PriKeyStr.replaceAll("-----BEGIN PRIVATE KEY-----", "");
        PriKeyStr = PriKeyStr.replaceAll("-----END PRIVATE KEY-----", "");
        PriKeyStr = PriKeyStr.strip();
        return PriKeyStr;
    }

    public static String readPubKey(String filename) throws IOException {
        String PubKeyStr = read(filename);
        PubKeyStr = PubKeyStr.replaceAll("-----BEGIN PUBLIC KEY-----", "");
        PubKeyStr = PubKeyStr.replaceAll("-----END PUBLIC KEY-----", "");
        PubKeyStr = PubKeyStr.strip();
        return PubKeyStr;
    }

    public static void main( String[] args ) throws Exception {
        String PriKeyStr = readPriKey("sm2PriKeyPkcs8.pem");
        String PubKeyStr = readPubKey("sm2PubKey.pem");
        System.out.println(PriKeyStr);
        System.out.println(PubKeyStr);
        byte[] msg = "common msg".getBytes();
        byte[] userId = "0xDktb".getBytes();
        byte[] sig = SM2Sign.signSm3WithSm2(msg, userId, PriKeyStr);
//        System.out.println(Hex.toHexString(sig));
        System.out.println(new String(Base64.encode(sig)));
    }
}
