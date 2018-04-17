package org.craftercms.commons.licensing;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.craftercms.commons.licensing.exception.LicenseNotFoundException;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;

public class LicensingRunner {

    public static void main(String[] args) throws IOException, LicenseNotFoundException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyPairGenerator keyPairGenerator = generateKeys(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        printKey(keyPair.getPrivate().getEncoded());
        printKey(keyPair.getPublic().getEncoded());
        write(keyPair);
        read();
        validate();
    }

    private static KeyPairGenerator generateKeys(int length) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(length);
        return keyPairGenerator;
    }

    private static void printKey(byte[] key) {
        System.out.println(key);
    }

    private static void read() throws IOException {
        Yaml yaml = new Yaml();
        InputStream inputStream = LicensingRunner.class.getClassLoader().getResourceAsStream("test4.lic");
        LicenseDetails licenseDetails = yaml.loadAs(inputStream, LicenseDetails.class);
        System.out.println(yaml.dumpAsMap(licenseDetails));
        //inputStream.close();
    }

    private static void write(KeyPair keyPair) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        LicenseDetails licenseDetails = new LicenseDetails();

        licenseDetails.setCustomerId("1");
        licenseDetails.setCustomerName("Ja");
        licenseDetails.setContractStartDate(new Date());
        licenseDetails.setContractEndDate(new Date());
        licenseDetails.setLicenseType(LicenseDetails.LicenseType.PERPETUAL);
        StudioLimit studioLimit = new StudioLimit();
        studioLimit.setNumberOfItems(1);
        studioLimit.setNumberOfUsers(1);
        studioLimit.setNumberOfSites(1);
        licenseDetails.setStudioLimit(studioLimit);
        EngineLimit engineLimit = new EngineLimit();
        engineLimit.setNumberOfSites(1);
        licenseDetails.setEngineLimit(engineLimit);
        ProfileLimit profileLimit = new ProfileLimit();
        profileLimit.setNumberOfSites(1);
        profileLimit.setNumberOfUsers(1);
        licenseDetails.setProfileLimit(profileLimit);
        SocialLimit socialLimit = new SocialLimit();
        socialLimit.setNumberOfItems(1);
        socialLimit.setNumberOfSites(1);
        licenseDetails.setSocialLimit(socialLimit);
        Yaml yaml = new Yaml();
        StringWriter writer = new StringWriter();
        yaml.dump(licenseDetails, writer);
        yaml.dumpAsMap(licenseDetails);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

        String outString = writer.toString();
        byte[] bytes = outString.getBytes();
        for (int i = 0; i * 1024 < bytes.length; i++) {
            byte[] part = Arrays.copyOfRange(bytes, i * 1024, (i+1)*1024);
            byte[] obuf = cipher.update(part, 0, part.length);
            if (obuf != null) System.out.write(Base64.getEncoder().encode(obuf));
        }
        byte[] obuf = cipher.doFinal();
        if (obuf != null)System.out.println(Base64.getEncoder().encode(obuf));
        System.out.println(yaml.dumpAsMap(licenseDetails));
    }

    public static void encryptLicense(String license) throws IOException, NoSuchAlgorithmException, PGPException, NoSuchProviderException, InvalidKeyException, SignatureException {
        genKeyPair();
        FileInputStream pubKeyIs = new FileInputStream("pub.dat");
        FileOutputStream cipheredFileIs = new FileOutputStream("crafter.lic");
        encryptFile(cipheredFileIs, license, readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();
    }

    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPPublicKey key = null;

        //
        // iterate through the key rings.
        //
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = kIt.next();

                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }

    public static void genKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, PGPException, SignatureException, InvalidKeyException {
        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        FileOutputStream fos1 = new FileOutputStream("pub.dat");
        FileOutputStream fos2 = new FileOutputStream("secret.dat");
        exportKeyPair(fos1, fos2, kp.getPublic(), kp.getPrivate(), "dejan", "dejan".toCharArray(), true);
        fos1.close();
        fos2.close();
    }

    public static void exportKeyPair(
            OutputStream secretOut,
            OutputStream    publicOut,
            PublicKey       publicKey,
            PrivateKey      privateKey,
            String          identity,
            char[]          passPhrase,
            boolean         armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException
    {
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }


        PGPPublicKey a = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
        RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privateKey;
        RSASecretBCPGKey privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
        PGPPrivateKey b = new PGPPrivateKey(a.getKeyID(), a.getPublicKeyPacket(), privPk);

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair keyPair = new PGPKeyPair(a,b);
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        secretKey.encode(secretOut);

        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey    key = secretKey.getPublicKey();

        key.encode(publicOut);

        publicOut.close();
    }

    public static void validate() throws LicenseNotFoundException {
        LicenseValidator lv = new SimpleLicenseValidator();
        System.out.println("Exists: " +lv.licenseExists("licensing/src/main/resources/test4.lic"));
        System.out.println("Expired: " +lv.licenseExpired("licensing/src/main/resources/test4.lic"));
        System.out.println("Violated: " +lv.licenseViolated("licensing/src/main/resources/test4.lic"));
        System.out.println("Validate Limit: " +lv.validateLimit("licensing/src/main/resources/test4.lic",
                LicenseModule.ENGINE, LimitType.SITE, 1));
    }
}
