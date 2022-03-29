package pdfboxEsign.esign.pdfsigner;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class PdfSignResult {
    List<String> signedFiles;
    List<String> failedFiles;
}
