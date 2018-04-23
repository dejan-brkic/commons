package org.craftercms.commons.licensing;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.craftercms.commons.licensing.exception.LicenseNotFoundException;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.time.Instant;
import java.util.Iterator;

public class SimpleLicenseValidator implements LicenseValidator {

    protected String licenseLocation;
    protected String keyLocation;
    protected String password;

    @Override
    public boolean licenseExists() {
        Resource resource = new ClassPathResource(licenseLocation);
        return resource != null && resource.exists();
    }

    @Override
    public boolean licenseExpired() throws LicenseNotFoundException {
        if (licenseExists()) {
            LicenseDetails licenseDetails = null;
            try {
                licenseDetails = loadLicence(licenseLocation);
            } catch (Exception e) {
                throw new LicenseNotFoundException(e);
            }
            Instant licenseTimestamp = licenseDetails.getContractEndDate().toInstant();
            if (licenseTimestamp.isBefore(Instant.now())) {
                return true;
            }
        } else {
            throw new LicenseNotFoundException();
        }
        return false;
    }

    @Override
    public boolean licenseViolated() throws LicenseNotFoundException {
        if (licenseExists()) {
            LicenseDetails licenseDetails = null;
            try {
                licenseDetails = loadLicence(licenseLocation);
            } catch (Exception e) {
                throw new LicenseNotFoundException(e);
            }
            return licenseDetails == null;
        } else {
            throw new LicenseNotFoundException();
        }
    }

    @Override
    public boolean validateLimit(LicenseModule module, LimitType limitType, int currentValue) throws LicenseNotFoundException {
        boolean toRet = false;
        if (licenseExists()) {
            LicenseDetails licenseDetails = null;
            try {
                licenseDetails = loadLicence(licenseLocation);
            } catch (Exception e) {
                throw new LicenseNotFoundException(e);
            }
            switch (module) {
                case ENGINE:
                    toRet = engineLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case PROFILE:
                    toRet = profileLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case SOCIAL:
                    toRet = socialLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                case STUDIO:
                    toRet = studioLicenseLimitsValidation(licenseDetails, limitType, currentValue);
                    break;
                default:
                    break;
            }
        } else {
            throw new LicenseNotFoundException();
        }

        return toRet;
    }

    private LicenseDetails loadLicence(String licenseLocation) throws Exception {
        FileInputStream cipheredFileIs = new FileInputStream(licenseLocation);
        FileInputStream privKeyIn = new FileInputStream(keyLocation);
        String decryptedLicense = decryptFile(cipheredFileIs, privKeyIn, password.toCharArray());
        LicenseDetails licenseDetails = null;
        Yaml yaml = new Yaml();
        licenseDetails = yaml.loadAs(decryptedLicense, LicenseDetails.class);
        cipheredFileIs.close();
        privKeyIn.close();
        return licenseDetails;
    }

    private String decryptFile(InputStream in, InputStream keyIn, char[] passwd) throws IOException, PGPException {
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

    private PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        PBESecretKeyDecryptor a = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

        return pgpSecKey.extractPrivateKey(a);
    }

    private boolean engineLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        switch (limitType) {
            case SITE:
                EngineLimit engineLimit = licenseDetails.getEngineLimit();
                toRet = currentValue < engineLimit.getNumberOfSites();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean profileLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        ProfileLimit profileLimit = licenseDetails.getProfileLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < profileLimit.getNumberOfSites();
                break;
            case USER:
                toRet = currentValue < profileLimit.getNumberOfUsers();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean socialLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        SocialLimit socialLimit = licenseDetails.getSocialLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < socialLimit.getNumberOfSites();
                break;
            case ITEM:
                toRet = currentValue < socialLimit.getNumberOfItems();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    private boolean studioLicenseLimitsValidation(LicenseDetails licenseDetails, LimitType limitType,
                                                  int currentValue) {
        boolean toRet = false;
        StudioLimit studioLimit = licenseDetails.getStudioLimit();
        switch (limitType) {
            case SITE:
                toRet = currentValue < studioLimit.getNumberOfSites();
                break;
            case DESCRIPTOR:
                toRet = currentValue < studioLimit.getNumberOfDescriptors();
                break;
            case ASSET:
                toRet = currentValue < studioLimit.getNumberOfAssets();
                break;
            case USER:
                toRet = currentValue < studioLimit.getNumberOfUsers();
                break;
            default:
                toRet = true;
                break;
        }
        return toRet;
    }

    public String getLicenseLocation() {
        return licenseLocation;
    }

    public void setLicenseLocation(String licenseLocation) {
        this.licenseLocation = licenseLocation;
    }

    public String getKeyLocation() {
        return keyLocation;
    }

    public void setKeyLocation(String keyLocation) {
        this.keyLocation = keyLocation;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
