package com.example.myapplication2;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Color;
import android.os.Bundle;

import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;


public class MainActivity extends AppCompatActivity {

    private TextView res1, res2, res3;
    private EditText etServerName, etServerPort;
    private Button btnClientConnect;
    private String serverName;
    private int serverPort;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etServerName = findViewById(R.id.etServerName);
        etServerPort = findViewById(R.id.etServerPort);
        btnClientConnect = findViewById(R.id.btnClientConnect);
        res1 = findViewById(R.id.res1);
        res2 = findViewById(R.id.res2);
        res3 = findViewById(R.id.res3);

    } // onCreate

    public void onClickConnect(View view){
        // when you press the button

        serverName = etServerName.getText().toString();
        serverPort = Integer.parseInt(etServerPort.getText().toString());


        new Thread(new Runnable() {
            @Override
            public void run() {
                try {

                    Socket socket = new Socket(serverName, serverPort);

                    // get input/output streams
                    BufferedReader br_input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    OutputStream output_client_byte = socket.getOutputStream();

                    //-------------------- Creation of the KeyPair ------------------------
                    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);

                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

                    keyPairGenerator.initialize(
                            new KeyGenParameterSpec.Builder("key1", KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                    //.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                                    .setDigests(KeyProperties.DIGEST_NONE)
                                    //.setDigests(KeyProperties.DIGEST_SHA256,
                                    //        KeyProperties.DIGEST_SHA384,
                                    //        KeyProperties.DIGEST_SHA512)
                                    // Only permit the private key to be used if the user
                                    // authenticated within the last five minutes.
                                    //.setUserAuthenticationRequired(true) //Richiede la presenza di una protezione del dispositivo (in caso di assenza di protezione lancia una eccezione)
                                    //.setUserAuthenticationValidityDurationSeconds(5 * 60)
                                    .setKeySize(2048)
                                    // Request an attestation with challenge "hello world".
                                    .setAttestationChallenge("hello world".getBytes("UTF-8"))
                                    .build());

                    keyPairGenerator.generateKeyPair();

                    String dataToSign = "Cybersecurity for Embedded Systems";

                    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("key1", null);

                    PrivateKey privateKey = privateKeyEntry.getPrivateKey();

                    // -------------------------- Signature Generation --------------------------
                    // message hashing
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] dataToHash = dataToSign.getBytes(StandardCharsets.UTF_8);
                    byte[] hashedMessage = digest.digest(dataToHash);

                    // Concatenate ID (in this example for SHA256) and message in this order
                    byte[] id = new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
                    byte[] idHashedMessage = new byte[id.length + hashedMessage.length];
                    System.arraycopy(id, 0, idHashedMessage, 0, id.length);
                    System.arraycopy(hashedMessage, 0, idHashedMessage, id.length, hashedMessage.length);

                    // generate actual signature
                    byte[] signature_byte = signData(idHashedMessage, privateKey);

                    // 1) send signature (byte[])
                    output_client_byte.write(signature_byte);
                    output_client_byte.flush();

                    // 2) extract certificates chain
                    Certificate[] certs = keyStore.getCertificateChain("key1");

                    // print on standard output the device TEE serial number
                    printDeviceTEESerialNumber(certs[0]);

                    // send to server each certificate byte[]
                    for(int i=0; i<4; i++){

                        byte[] cert_byte = certs[i].getEncoded();

                        // trigger server error
                        // cert_byte[20] = -36;

                        // send certificate length
                        output_client_byte.write(ByteBuffer.allocate(4).putInt(cert_byte.length).array());
                        output_client_byte.flush();

                        // send actual certificate
                        output_client_byte.write(cert_byte);
                        output_client_byte.flush();
                    }

                    // Receives results from the server
                    String outcome = br_input.readLine();

                    // results[0] = result_certs
                    // results[1] = result_signature
                    // results[2] = valid_tee
                    String[] results = outcome.split(",");

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if(results[0].equals("false")){
                                res1.setTextColor(Color.RED);
                            }
                            else{
                                res1.setTextColor(Color.GREEN);
                            }
                            if(results[1].equals("false")){
                                res2.setTextColor(Color.RED);
                            }
                            else{
                                res2.setTextColor(Color.GREEN);
                            }
                            if(results[2].equals("false")){
                                res3.setTextColor(Color.RED);
                            }
                            else{
                                res3.setTextColor(Color.GREEN);
                            }

                            res1.setText(results[0]);
                            res2.setText(results[1]);
                            res3.setText(results[2]);
                        }
                    });
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }

        public String extractSN(String original) {

            // define expression to find the pattern "KEY=VALUE"
            Pattern pattern = Pattern.compile("SERIALNUMBER=(.*?)(,|$)");

            // find the pattern
            Matcher matcher = pattern.matcher(original);

            String code = "";
            // extract the code
            if (matcher.find()) {
                code = matcher.group(1).trim();
            }
        return code;
    }

    private void printDeviceTEESerialNumber(Certificate cert){
        X509Certificate X509cert0 = null;
        if(cert instanceof X509Certificate)
            X509cert0 = (X509Certificate) cert;
        String issuerUniqueID = X509cert0.getIssuerX500Principal().toString();

        String serialNumber = extractSN(issuerUniqueID);
        System.out.println(serialNumber);
    }

    private byte[] signData( byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("NONEwithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}