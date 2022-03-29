package pdfboxEsign.esign.pdfsigner;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

@Slf4j
@AllArgsConstructor
public class TC3 implements SignatureInterface {

    private ContentSigner contentSigner;

    private String tsaURL;

    private Certificate[] certificateChain;

//    public byte[] sign(InputStream content)
//    {
//// Original code for older BC version.
////      CMSProcessableInputStream input = new CMSProcessableInputStream(content);
////      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
////      List<Certificate> certList = Arrays.asList(cert);
////      CertStore certStore = null;
////      try{
////          certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), provider);
////          gen.addSigner(privKey, (X509Certificate) certList.get(0), CMSSignedGenerator.DIGEST_SHA256);
////          gen.addCertificatesAndCRLs(certStore);
////          CMSSignedData signedData = gen.generate(input, false, provider);
////          return signedData.getEncoded();
////      }catch (Exception e){}
////      return null;
//// Replacement code adapted from CreateSignature
//        try {
//            BouncyCastleProvider BC = new BouncyCastleProvider();
//            Store<?> certStore = new JcaCertStore(Collections.singletonList(cert[0]));
//
//            CMSTypedDataInputStream input = new CMSTypedDataInputStream(content);
//            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
//            ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BC).build(privKey);
//
//            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
//                    new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(sha512Signer, new X509CertificateHolder(cert[0].getEncoded())
//            ));
//            gen.addCertificates(certStore);
//            CMSSignedData signedData = gen.generate(input, false);
//
//            if (true)
//            { // DER-encode signature container
//                ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                DEROutputStream dos = new DEROutputStream(baos);
//                dos.writeObject(signedData.toASN1Structure());
//                return baos.toByteArray();
//            }
//            else
//                return signedData.getEncoded();
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

    public byte[] sign(InputStream content) throws IOException {
        try {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate signingCertificate = (X509Certificate) certificateChain[0];

            DigestCalculatorProvider digestCalculator = new JcaDigestCalculatorProviderBuilder().build();
            SignerInfoGenerator signerInfo = new JcaSignerInfoGeneratorBuilder(digestCalculator).build(contentSigner, signingCertificate);
            gen.addSignerInfoGenerator(signerInfo);
            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);

            ValidationTimeStamp validation = new ValidationTimeStamp(tsaURL);
            signedData = validation.addSignedTimeStamp(signedData);

            return signedData.getEncoded();
        } catch (GeneralSecurityException | OperatorCreationException | CMSException e) {
            log.error("Unable to get certificates", e);
            throw new IOException(e);
        }
    }

    public void doSignTwoRevisions(File inputDocument, File outputDocument) throws Exception
    {
        InputStream inputStream = new FileInputStream(inputDocument);
        OutputStream outputStream = new FileOutputStream(outputDocument);

        ByteArrayOutputStream inMemOut = new ByteArrayOutputStream();

        byte inputBytes[] = IOUtils.toByteArray(inputStream);

        PDDocument pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));

//        PDJpeg ximage = new PDJpeg(pdDocument, ImageIO.read(logoStream));
//        PDPage page = (PDPage) pdDocument.getDocumentCatalog().getAllPages().get(0);
//        PDPageContentStream contentStream = new PDPageContentStream(pdDocument, page, true, true);
//        contentStream.drawXObject(ximage, 50, 50, 356, 40);
//        contentStream.close();
//
//        page.getCOSObject().setNeedToBeUpdated(true);
//        page.getResources().getCOSObject().setNeedToBeUpdated(true);
//        page.getResources().getCOSDictionary().getDictionaryObject(COSName.XOBJECT).setNeedToBeUpdate(true);
//        ximage.getCOSObject().setNeedToBeUpdate(true);
        PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();

        catalog.getCOSObject().setNeedToBeUpdated(true);
        catalog.getPages().getCOSObject().setNeedToBeUpdated(true);

        PDAcroForm form = catalog.getAcroForm();

        form.getCOSObject().setNeedToBeUpdated(true);
        form.getDefaultResources().getCOSObject().setNeedToBeUpdated(true);

        for (PDField field : form.getFields()) {
//            PDField field = form.getField(form.getFields().get(9).getFullyQualifiedName());
            if (!field.getFullyQualifiedName().startsWith("txt")) {
                continue;
            }
//            field.getWidgets().get(0).setHidden(false);
//            for (PDAnnotationWidget widget : field.getWidgets()) {
//                widget.
//            }
            field.setValue("Bikram");

            field.getCOSObject().setNeedToBeUpdated(true);
            field.getAcroForm().getCOSObject().setNeedToBeUpdated(true);

            ((COSDictionary) field.getCOSObject().getDictionaryObject("AP")).setNeedToBeUpdated(true);

            ((COSDictionary) ((COSDictionary) field.getCOSObject().getDictionaryObject("AP")).getDictionaryObject("N")).setNeedToBeUpdated(true);
        }

        pdDocument.saveIncremental(inMemOut);
        pdDocument.close();

        byte[] editedBytes = inMemOut.toByteArray();
        ByteArrayInputStream inMemIn = new ByteArrayInputStream(editedBytes);

        pdDocument = PDDocument.load(inMemIn);

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("signer name");
        signature.setLocation("signer location");
        signature.setReason("reason for signature");
        signature.setSignDate(Calendar.getInstance());

        pdDocument.addSignature(signature, this);

        pdDocument.saveIncremental(outputStream);
        pdDocument.close();
    }
}
