package pdfboxEsign.esign.pdfsigner;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;
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
public class SignThePdf implements SignatureInterface {

  private ContentSigner contentSigner;

  private String tsaURL;

  private Certificate[] certificateChain;

  public SignThePdf() {
  }

  public SignThePdf(ContentSigner contentSigner, String tsaURL, Certificate[] certificateChain) {
    this.contentSigner = contentSigner;
    this.tsaURL = tsaURL;
    this.certificateChain = certificateChain;
  }

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


  public void signThePdf(File inputDocument, File outputDocument) throws Exception
  {
    InputStream inputStream = new FileInputStream(inputDocument);
    OutputStream outputStream = new FileOutputStream(outputDocument);

    byte inputBytes[] = IOUtils.toByteArray(inputStream);
    PDDocument pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));

    PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();

    catalog.getCOSObject().setNeedToBeUpdated(true);
    catalog.getPages().getCOSObject().setNeedToBeUpdated(true);

    PDAcroForm form = catalog.getAcroForm();

    form.getCOSObject().setNeedToBeUpdated(true);
    form.getDefaultResources().getCOSObject().setNeedToBeUpdated(true);

    int count = 0;
    for (PDField field : form.getFieldTree()) {
      if (count >= 5) {
        break;
      }
      if (field instanceof PDTextField) {
        count++;
        PDTextField textField = (PDTextField) field;
        textField.setValue("----------before-------");
        field.getCOSObject().setNeedToBeUpdated(true);
        field.getAcroForm().getCOSObject().setNeedToBeUpdated(true);

        ((COSDictionary) field.getCOSObject().getDictionaryObject("AP")).setNeedToBeUpdated(true);

        ((COSDictionary) ((COSDictionary) field.getCOSObject()
            .getDictionaryObject("AP")).getDictionaryObject("N")).setNeedToBeUpdated(true);
      }
    }
    ByteArrayOutputStream inMemOut = new ByteArrayOutputStream();
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

    inputStream = new FileInputStream(inputDocument);
    inputBytes = IOUtils.toByteArray(inputStream);
    pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));
    catalog = pdDocument.getDocumentCatalog();

    catalog.getCOSObject().setNeedToBeUpdated(true);
    catalog.getPages().getCOSObject().setNeedToBeUpdated(true);

    form = catalog.getAcroForm();

    form.getCOSObject().setNeedToBeUpdated(true);
    form.getDefaultResources().getCOSObject().setNeedToBeUpdated(true);

    count = 0;
    for (PDField field : form.getFieldTree()) {
      count++;
      if (count > 5) {
        if (field instanceof PDTextField) {
          PDTextField textField = (PDTextField) field;
          textField.setValue("----------after-------");
          field.getCOSObject().setNeedToBeUpdated(true);
          field.getAcroForm().getCOSObject().setNeedToBeUpdated(true);

          ((COSDictionary) field.getCOSObject().getDictionaryObject("AP")).setNeedToBeUpdated(true);

          ((COSDictionary) ((COSDictionary) field.getCOSObject()
              .getDictionaryObject("AP")).getDictionaryObject("N")).setNeedToBeUpdated(true);
        }
      }
    }

    inMemOut = new ByteArrayOutputStream();
    pdDocument.saveIncremental(inMemOut);
    pdDocument.close();

    editedBytes = inMemOut.toByteArray();
    inMemIn = new ByteArrayInputStream(editedBytes);

    pdDocument = PDDocument.load(inMemIn);
    signature = new PDSignature();
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


  public void signPreviouslySignedPdf(File inputDocument, File outputDocument) throws Exception
  {

    InputStream inputStream = new FileInputStream(inputDocument);
    OutputStream outputStream = new FileOutputStream(outputDocument);

    ByteArrayOutputStream inMemOut = new ByteArrayOutputStream();

    byte inputBytes[] = IOUtils.toByteArray(inputStream);
    PDDocument pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));

    PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();

    catalog.getCOSObject().setNeedToBeUpdated(true);
    catalog.getPages().getCOSObject().setNeedToBeUpdated(true);

    PDAcroForm form = catalog.getAcroForm();

    form.getCOSObject().setNeedToBeUpdated(true);
    form.getDefaultResources().getCOSObject().setNeedToBeUpdated(true);
    int count = 0;
    for (PDField field : form.getFieldTree()) {
      count++;
      if (count > 5) {
        if (field instanceof PDTextField) {
          PDTextField textField = (PDTextField) field;
          textField.setValue("----------afterrrrr-------");
          field.getCOSObject().setNeedToBeUpdated(true);
          field.getAcroForm().getCOSObject().setNeedToBeUpdated(true);

          ((COSDictionary) field.getCOSObject().getDictionaryObject("AP")).setNeedToBeUpdated(true);

          ((COSDictionary) ((COSDictionary) field.getCOSObject()
              .getDictionaryObject("AP")).getDictionaryObject("N")).setNeedToBeUpdated(true);
        }
      }
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
