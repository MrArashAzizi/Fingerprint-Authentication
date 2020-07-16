package ir.arash.edu.fingerprintauthenticate;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AuthActivity extends AppCompatActivity {

    private static final String KEY_NAME = "FingerprintKey";
    Cipher cipher;
    KeyStore keystore;
    private TextView txtResult;
    private KeyguardManager keyguardManager;
    private FingerprintManager fingerprintManager;
    private ImageView imageView;

    @Override
    protected void onCreate(Bundle savedInstanceState) throws SecurityException {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);
        txtResult = findViewById(R.id.Result);
        imageView = findViewById(R.id.img_finger);
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
        checkperms();

        if (!hasPermission()) {
            txtResult.setText("Fingerprint permission not enabled");
        }

        else if (fingerprintManager.isHardwareDetected())
        {
            if (!fingerprintManager.hasEnrolledFingerprints()) {
                txtResult.setText("Register at least one fingerprint in device settings");
            }

            else if (!keyguardManager.isKeyguardSecure()) {
                txtResult.setText("Lock screen security not enabled in settings");
            }

            else {
                generateKey();

                if (cipherInit()) {
                    FingerprintManager.CryptoObject cryptoObject =
                            new FingerprintManager.CryptoObject(cipher);
                    CancellationSignal cancellationSignal = new CancellationSignal();
                    fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationError(int errorCode, CharSequence errString) {
                                    txtResult.setText("Fingerprint Authentication Error \n" + errString);
                                    Toast.makeText(AuthActivity.this,
                                            "Error : \n" + errString,
                                            Toast.LENGTH_SHORT).show();
                                    finish();
                                }

                                @Override
                                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                    txtResult.setText("Fingerprint Authentication Help \n" + helpString);
                                }

                                @Override
                                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                    txtResult.setText("Fingerprint Authentication Succeeded :)\n");
                                    imageView.setColorFilter(Color.GREEN);
                                    txtResult.setTextColor(Color.GREEN);
                                    //txtResult.setTextColor(Color.rgb(50, 200, 50));
                                    /*Intent intent = new Intent(AuthActivity.this, MainActivity.class);
                                    startActivity(intent);
                                    finish();*/
                                }

                                @Override
                                public void onAuthenticationFailed() {
                                    txtResult.setText("Fingerprint Authentication Failed");
                                }
                            },
                            null);
                }
            }
        } else {
            Toast.makeText(this, "error!", Toast.LENGTH_SHORT).show();
        }


    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() {
        try {
            keystore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            e.printStackTrace();
        }


        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }


        try {
            keystore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException |
                InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }


        try {
            keystore.load(null);
            SecretKey key = (SecretKey) keystore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        }
        catch (KeyPermanentlyInvalidatedException e) {
            return false;
        }
        catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }

    }

    private boolean hasPermission() {
        return ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void checkperms() {
        if (!hasPermission()) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.USE_FINGERPRINT},
                    0);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == 0) {
            if (grantResults[0] != PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Fingerprint permission denied :(", Toast.LENGTH_SHORT).show();
                finish();
            }
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
}