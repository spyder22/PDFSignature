package pdfboxEsign.esign.pdfsigner;

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignRequest;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignResponse;
import com.google.api.services.cloudkms.v1.model.Digest;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author Akhilesh Kumar
 * @version 1.0
 * @date 01/06/2021 20:50
 */
@Slf4j
public class GoogleKMSContentSigner implements ContentSigner {
	private ByteArrayOutputStream outputStream;
	private final AlgorithmIdentifier sigAlgId;
	private final CloudKMS kms;
	private final String keyPath;

	/**
	 * Initialise Google KMS content signer
	 *
	 * @param kms
	 * @param keyPath
	 */
	public GoogleKMSContentSigner(CloudKMS kms, String keyPath, String signAlgo) {
		this.kms = kms;
		this.keyPath = keyPath;
		this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signAlgo);
		this.outputStream = new ByteArrayOutputStream();
	}

	@Override
	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return this.sigAlgId;
	}

	@Override
	public OutputStream getOutputStream() {
		return this.outputStream;
	}

	@Override
	public byte[] getSignature() {
		try {
			byte[] signedAttributeSet = outputStream.toByteArray();
			// we have read whole data and sent for signature, now lets accumulate new data
			this.outputStream.reset();

			return signAsymmetric(signedAttributeSet);

		} catch (IOException | NoSuchAlgorithmException e) {
			log.error("Unable to sign using GCP KMS", e);
			throw new RuntimeException("Unable to sign with KMS");
		}
	}

	/**
	 * Create a signature for a message using a private key stored on Cloud KMS
	 * <p>
	 * Requires:
	 * java.security.MessageDigest
	 * java.util.Base64
	 */
	private byte[] signAsymmetric(byte[] message)
			throws IOException, NoSuchAlgorithmException {
		Digest digest = new Digest();

		// Note: some key algorithms will require a different hash function
		// For example, EC_SIGN_P384_SHA384 requires SHA-384
		digest.encodeSha256(MessageDigest.getInstance("SHA-256").digest(message));

		return doSign(digest);
	}

	private byte[] signDigestAsymmetric(byte[] digestedMessage)
			throws IOException {
		Digest digest = new Digest();

		digest.encodeSha256(digestedMessage);

		return doSign(digest);
	}

	private byte[] doSign(Digest digest) throws IOException {
		AsymmetricSignRequest signRequest = new AsymmetricSignRequest();
		signRequest.setDigest(digest);

		AsymmetricSignResponse response = kms.projects()
				.locations()
				.keyRings()
				.cryptoKeys()
				.cryptoKeyVersions()
				.asymmetricSign(keyPath, signRequest)
				.execute();
		return Base64.getMimeDecoder().decode(response.getSignature());
	}
}
