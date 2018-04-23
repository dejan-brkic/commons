package org.craftercms.commons.licensing;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.craftercms.commons.licensing.exception.LicenseNotFoundException;
import org.yaml.snakeyaml.Yaml;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
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
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;

public class LicensingRunner {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = generateKeys(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        printKey(keyPair.getPrivate().getEncoded());
        printKey(keyPair.getPublic().getEncoded());
        write(keyPair);
        //Thread.sleep(10000);
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

    private static void read() throws Exception {
        /*
        Yaml yaml = new Yaml();
        InputStream inputStream = LicensingRunner.class.getClassLoader().getResourceAsStream("test4.lic");
        LicenseDetails licenseDetails = yaml.loadAs(inputStream, LicenseDetails.class);
        System.out.println(yaml.dumpAsMap(licenseDetails));
        //inputStream.close();

        FileInputStream cipheredFileIs = new FileInputStream("licensing/src/main/resources/crafter.lic");
        FileInputStream privKeyIn = new FileInputStream("licensing/src/main/resources/secret.dat");
        String decryptedLicense = decryptFile(cipheredFileIs, privKeyIn, "dejan".toCharArray());
        LicenseDetails licenseDetails = null;
        Yaml yaml = new Yaml();
        licenseDetails = yaml.loadAs(decryptedLicense, LicenseDetails.class);
        cipheredFileIs.close();
        privKeyIn.close();
        System.out.println(yaml.dumpAsMap(licenseDetails));*/

        FileInputStream cipheredFileIs = new FileInputStream("licensing/src/main/resources/crafter.lic");
        FileInputStream privKeyIn = new FileInputStream("licensing/src/main/resources/secret.dat");
        FileOutputStream plainTextFileIs =
                new FileOutputStream("licensing/src/main/resources/crafter-clear-decrypt.lic");
        decryptFile2(cipheredFileIs, plainTextFileIs, privKeyIn, "dejan".toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

    public static void decryptFile2(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
            throws Exception
    {
        BcKeyFingerprintCalculator bcKeyFingerprintCalculator = new BcKeyFingerprintCalculator();
        Security.addProvider(new BouncyCastleProvider());
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in, bcKeyFingerprintCalculator);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof  PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();
            sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);

        InputStream clear = pbe.getDataStream(b);



        PGPObjectFactory plainFact = new PGPObjectFactory(clear, bcKeyFingerprintCalculator);

        Object message = plainFact.nextObject();

        if (message instanceof  PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), bcKeyFingerprintCalculator);

            message = pgpFact.nextObject();
        }

        if (message instanceof  PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
        } else if (message instanceof  PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }

    public static String decryptFile(InputStream in, InputStream keyIn, char[] passwd)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof  PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();
            sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);

        InputStream clear = pbe.getDataStream(b);

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

            message = pgpFact.nextObject();
        }

        StringBuilder sb = new StringBuilder();
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            sb.append(IOUtils.toString(unc));
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
        return sb.toString();
    }

    public static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        PBESecretKeyDecryptor a = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

        return pgpSecKey.extractPrivateKey(a);
    }

    private static void write(KeyPair keyPair) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchProviderException, SignatureException, PGPException {
        LicenseDetails licenseDetails = new LicenseDetails();

        licenseDetails.setCustomerId("1");
        licenseDetails.setCustomerName("Ja");
        licenseDetails.setContractStartDate(new Date());
        licenseDetails.setContractEndDate(new Date());
        licenseDetails.setLicenseType(LicenseDetails.LicenseType.PERPETUAL);
        StudioLimit studioLimit = new StudioLimit();
        studioLimit.setNumberOfDescriptors(1);
        studioLimit.setNumberOfAssets(1);
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
        FileWriter fileWriter = new FileWriter("licensing/src/main/resources/crafter-clear.lic");
        yaml.dump(licenseDetails, writer);
        yaml.dump(licenseDetails, fileWriter);
        System.out.println(yaml.dumpAsMap(licenseDetails));
        //FileOutputStream licenseFile = new FileOutputStream("licensing/src/main/resources/crafter.lic");
        //licenseFile.write(writer.toString().getBytes());

        encryptLicense(writer.toString());
/*
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
        System.out.println(yaml.dumpAsMap(licenseDetails));*/
    }

    public static void encryptLicense(String license) throws IOException, NoSuchAlgorithmException, PGPException, NoSuchProviderException, InvalidKeyException, SignatureException {
        genKeyPair();
        FileInputStream pubKeyIs = new FileInputStream("licensing/src/main/resources/pub.dat");
        FileOutputStream cipheredFileIs = new FileOutputStream("licensing/src/main/resources/crafter.lic");
        encryptFile(cipheredFileIs, "licensing/src/main/resources/crafter-clear.lic", readPublicKey(pubKeyIs), true,
                true);
        cipheredFileIs.close();
        pubKeyIs.close();
    }

    public static void encryptFile(OutputStream out, String fileName,
                            PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);
        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());
        cPk.addMethod(d);
        byte[] bytes = bOut.toByteArray();
        OutputStream cOut = cPk.open(out, bytes.length);
        cOut.write(bytes);
        cOut.close();
        out.close();
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
        FileOutputStream fos1 = new FileOutputStream("licensing/src/main/resources/pub.dat");
        FileOutputStream fos2 = new FileOutputStream("licensing/src/main/resources/secret.dat");
        exportKeyPair(fos2, fos1, kp.getPublic(), kp.getPrivate(), "dejan", "dejan".toCharArray(), true);
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
        System.out.println("Exists: " +lv.licenseExists());
        System.out.println("Expired: " +lv.licenseExpired());
        System.out.println("Violated: " +lv.licenseViolated());
        System.out.println("Validate Limit: " +lv.validateLimit(
                LicenseModule.ENGINE, LimitType.SITE, 1));
    }
}
