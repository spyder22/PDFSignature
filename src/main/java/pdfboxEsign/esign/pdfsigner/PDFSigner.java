package pdfboxEsign.esign.pdfsigner;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

/**
 * @author akhilesh k
 */
@Slf4j
public class PDFSigner implements SignatureInterface {

	private ContentSigner contentSigner;

	private String tsaURL;

	private Certificate[] certificateChain;

	public PDFSigner(ContentSigner contentSigner, String tsaURL, Certificate[] certificateChain) {
		this.contentSigner = contentSigner;
		this.tsaURL = tsaURL;
		this.certificateChain = certificateChain;
	}

	public PdfSignResult signPdf(String unSignedDir, String signedDirPath) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
		// Read file
		File inSignFile = new File(unSignedDir);
		File directoryName= new File(inSignFile.getParent());
		File[] filesToBeSigned = directoryName.listFiles();
		assert filesToBeSigned != null;

		List<String> signedFiles = new ArrayList<>();
		List<String> failedFiles = new ArrayList<>();

		for(File inFile : filesToBeSigned) {
			String fileName = inFile.getName();
			String documentName = fileName.substring(0, fileName.lastIndexOf('.'));

			// PDFbox object with file to be signed.
			PDDocument document = PDDocument.load(inFile);
			PDPage page = document.getPage(0);
			page.setRotation(90);

			InputStream inputStream = new FileInputStream(inFile);
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//			signature.setName("SignMe");
//			signature.setLocation("Bengaluru");
//			signature.setReason("Tamper Proofing");

			// the signing date, needed for valid signature
			signature.setSignDate(Calendar.getInstance());

//			FileOutputStream output = new FileOutputStream(outFile);
//			ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(output);
//			InputStream inputStream = externalSigning.getContent();
//			byte[] cmsSignature = sign(inputStream);
//			externalSigning.setSignature(cmsSignature);

			try {
				signature.getSignedContent(sign(inputStream));
				log.info("Signature generated for " + fileName);
			} catch (RuntimeException e) {
				log.error("Unable to generate the document signature using BouncyCastle, {}", e);
				failedFiles.add(inFile.toPath().toString());
				document.close();
				inputStream.close();
				continue;
			}

			SignatureOptions signatureOptions = new SignatureOptions();

			// Size can vary, but should be enough for purpose.
			signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

			// register signature dictionary and sign interface
			document.addSignature(signature, this, signatureOptions);

			// Creates the output file with _signed suffix.
			File outFile = new File(signedDirPath, documentName + ".pdf");
			// write incremental (only for signing purpose)
			try(FileOutputStream out = new FileOutputStream(outFile)) {
				document.saveIncremental(out);
				log.info("Signature added to the document " + fileName);
				signedFiles.add(inFile.toPath().toString());
			} catch (IOException e) {
				log.error("Unable to add the signature using pdfbox, {}", e);
				failedFiles.add(inFile.toPath().toString());
			}

			document.close();
			inputStream.close();
		}
		return new PdfSignResult(signedFiles, failedFiles);
	}

	/**
	 * SignatureInterface implementation.
	 * <p>
	 * This method will be called from inside of the pdfbox and create the PKCS #7 signature.
	 * <p>
	 * Used Bouncy castle to create PKCS #7 signature and further delegating it back to CreateSignature Class for pdf embedding.
	 *
	 */
	@Override
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
			log.error("Unable to get certificates, {}", e);
			throw new IOException(e);
		}
	}
}
