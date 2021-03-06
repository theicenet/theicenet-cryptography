import com.theicenet.cryptography.key.asymmetric.AsymmetricKeyService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MyComponent {

  private final AsymmetricKeyService ecdhKeyService;

  @Autowired
  public MyComponent(@Qualifier("ECDHKey_secpXXXk1") AsymmetricKeyService ecdhKeyService) {
    this.ecdhKeyService = ecdhKeyService;
  }

  public void generateRandomKeyPair() {
    // Generate a key with 256 bits length
    KeyPair keyPair = ecdhKeyService.generateKey(256);

    PublicKey publicKey = keyPair.getPublic(); // X.509 format publicKey
    PrivateKey privateKey = keyPair.getPrivate(); // PKCS#8 format privateKey
  }
}