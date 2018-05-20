package com.kieun.example.confirmationprompt;

import android.os.Bundle;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import android.security.ConfirmationAlreadyPresentingException;
import android.security.ConfirmationCallback;
import android.security.ConfirmationNotAvailableException;
import android.security.ConfirmationPrompt;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;

import com.google.android.material.navigation.NavigationView;

import androidx.annotation.Nullable;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.view.Menu;
import android.view.MenuItem;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

public class MainActivity extends AppCompatActivity
        implements NavigationView.OnNavigationItemSelectedListener {

    private static final String TAG = MainActivity.class.getName();
    private static final String KEY_NAME = "test";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = (NavigationView) findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);
    }

    @Override
    public void onBackPressed() {
        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @SuppressWarnings("StatementWithEmptyBody")
    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        if (id == R.id.nav_register) {
            // Register public key for confirmation prompt first
            // Check this device supports confirmation prompt
            if (!ConfirmationPrompt.isSupported(this)) {
                Log.w(TAG, "Confirmation Prompt is not supported on this device");
                return true;
            }

            // RP provided challenge
            byte[] challenge = UUID.randomUUID().toString().getBytes();
            try {
                generateKeyPair(KEY_NAME, true, challenge);
                Certificate[] certificateChain = getAttestationCertificateChain(KEY_NAME);
                // First entry of certificate chain is for Kpub
                // This certificate chain should be sent to RP, and then verified.
                // If verification is succeeded, RP should maintain Kpub.
                for (int i = 0; i < certificateChain.length; i++) {
                    Log.i(TAG, "Cert " + i + ": " + certificateChain[i].toString());
                    Log.i(TAG, "PubKey " + i + ": " + Base64.encodeToString(certificateChain[i].getPublicKey().getEncoded(), Base64.URL_SAFE));
                }
            } catch (Exception e) {
                Log.e(TAG, e.getLocalizedMessage());
            }

        } else if (id == R.id.nav_authentication) {
            String promptText = "prompt Text";
            String nonce = UUID.randomUUID().toString();
            byte[] extraData = (promptText + ":" + nonce).getBytes();

            // Create confirmation prompt
            ConfirmationPrompt confirmationPrompt = new ConfirmationPrompt.Builder(this)
                    .setPromptText(promptText)
                    .setExtraData(extraData)
                    .build();

            try {
                confirmationPrompt.presentPrompt(getMainExecutor(), new ConfirmationCallback() {
                    @Override
                    public void onConfirmed(byte[] dataThatWasConfirmed) {
                        super.onConfirmed(dataThatWasConfirmed);
                        try {
                            Signature signature = initSignature(KEY_NAME);
                            signature.update(dataThatWasConfirmed);
                            byte[] signatureBytes = signature.sign();

                            // dataThatWasConfirmed and signatureBytes should be sent to RP
                            // RP verifies the signature with Kpub and the message (dataThatWasConfirmed) is identical to the challenge
                            Log.i(TAG, "dataThatWasConfirmed: " + Base64.encodeToString(dataThatWasConfirmed, Base64.URL_SAFE));
                            Log.i(TAG, "signature: " + Base64.encodeToString(signatureBytes, Base64.URL_SAFE));
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public void onDismissed() {
                        super.onDismissed();
                    }

                    @Override
                    public void onCanceled() {
                        super.onCanceled();
                    }

                    @Override
                    public void onError(Throwable e) {
                        super.onError(e);
                    }
                });
            } catch (ConfirmationAlreadyPresentingException e) {
                confirmationPrompt.cancelPrompt();
            } catch (ConfirmationNotAvailableException e) {
                Log.w(TAG, "Confirmation Prompt is not supported on this device");
            }

        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    /**
     * Generate NIST P-256 EC Key pair for signing and verification
     * @param keyName
     * @param invalidatedByBiometricEnrollment
     * @param challenge
     * @return
     * @throws Exception
     */
    private KeyPair generateKeyPair(String keyName, boolean invalidatedByBiometricEnrollment, byte[] challenge) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                // Require the user to authenticate with a biometric to authorize every use of the key
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
                .setAttestationChallenge(challenge);

        keyPairGenerator.initialize(builder.build());

        return keyPairGenerator.generateKeyPair();
    }

    private Certificate[] getAttestationCertificateChain(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return keyStore.getCertificateChain(alias);
    }

    @Nullable
    private KeyPair getKeyPair(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {
            // Get public key
            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();
            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            // Return a key pair
            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    @Nullable
    private Signature initSignature (String keyName) throws Exception {
        KeyPair keyPair = getKeyPair(keyName);

        if (keyPair != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            return signature;
        }
        return null;
    }
}
