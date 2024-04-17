package com.example.keyattestationserver;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okhttp3.Cache;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    private TextView tvServerName, tvServerPort, tvStatus;
    private String serverIP = "192.168.43.107";
    private int serverPort = 1234;          // choose port > 1023 (avoid reserved as 8080)

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        serverThread = new ServerThread();

        tvServerName = findViewById(R.id.tvServerName);
        tvServerPort = findViewById(R.id.tvServerPort);
        tvStatus = findViewById(R.id.tvStatus);
        tvServerName.setText((serverIP));
        tvServerPort.setText(String.valueOf(serverPort));
    }

    private ServerThread serverThread;

    public void onClickStartServer(View view){
        serverThread.startServer();
    }

    public void onClickStopServer(View view){
        if(serverThread != null)
            serverThread.stopServer();
    }

    class ServerThread extends Thread implements Runnable {

        private boolean serverRunning;
        private ServerSocket serverSocket;

        public void startServer(){
            if(serverRunning != true) {
                serverRunning = true;
                start();
            }
        }

        @Override
        public void run() {
            try {
                // new socket created!!

                serverSocket = new ServerSocket(serverPort);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        tvStatus.setText("Waiting for clients..");
                    }
                });

                // waiting and accept new clients
                while(serverRunning){

                    // for each client that arrives create a new socket and accept
                    Socket socket = serverSocket.accept();

                    InputStream inputStream = socket.getInputStream();
                    PrintWriter br_output = new PrintWriter(socket.getOutputStream(), true);
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

                    // 1) receive signature byte[]
                    byte[] sigByte = new byte[256];
                    inputStream.read(sigByte);

                    // 2) receive of the 4 certificates
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate[] X509certs = new X509Certificate[4];

                    byte[] lenByte = new byte[4];
                    int len;

                    for(int i=0; i<4; i++){
                        // read cert length
                        dataInputStream.readFully(lenByte);
                        len = ByteBuffer.wrap(lenByte).getInt();

                        byte[] certByte = new byte[len];

                        // read as many bytes as cert length
                        dataInputStream.readFully(certByte);

                        InputStream in = new ByteArrayInputStream(certByte);
                        X509certs[i] = (X509Certificate)certFactory.generateCertificate(in);
                    }

                    // 3) verify cert. chain
                    boolean result_certs;
                    try{
                        result_certs = verifyCertChain(X509certs);
                    } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                             NoSuchProviderException | SignatureException | IOException e) {
                        result_certs = false;
                    }

                    PublicKey pubKey = X509certs[0].getPublicKey();

                    // 5) verify signature
                    boolean result_signature = verifySignature("Cybersecurity for Embedded Systems",
                            sigByte, pubKey);

                    // 6) verify TEE
                    // hardcoded tees
                    String teeO = "01ee2c9e32c60dde";
                    String teeX = "c890c38cca35bf88591d4ff1b2c403ac";
                    String teeLenovo = "a78f33b4770a4eb6957a5315fa07579c";

                    // TEE_SN extracted from the inner certificate
                    String issuerUniqueID = X509certs[0].getIssuerX500Principal().toString();
                    String serialNumber = extractSN(issuerUniqueID);

                    boolean valid_tee;
                    if (serialNumber.equals(teeLenovo))
                        valid_tee = true;
                    else
                        valid_tee = false;

                    // send results to the Client
                    br_output.println(
                            String.valueOf(result_certs) + "," +
                            String.valueOf(result_signature) + "," +
                            String.valueOf(valid_tee)
                    );

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            tvStatus.setText("Results sent to Client!");
                        }
                    });

                    socket.close();
                }

            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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

        private boolean verifySignature(String data, byte[] signature, PublicKey publicKey) throws Exception {
            Signature verifySignature = Signature.getInstance("SHA256withRSA");
            verifySignature.initVerify(publicKey);
            verifySignature.update(data.getBytes(StandardCharsets.UTF_8));
            return verifySignature.verify(signature);
        }

        private boolean verifyCertChain(X509Certificate[] certs)
                throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException, IOException {

            final String GOOGLE_ROOT_CA_PUB_KEY =
                    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU"
                            + "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j"
                            + "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y"
                            + "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X"
                            + "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI"
                            + "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB"
                            + "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q"
                            + "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp"
                            + "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7"
                            + "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82"
                            + "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+"
                            + "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

            boolean certStatus = false;
            boolean[] certsStatus = new boolean[4];
            boolean certGoogle;

            X509Certificate parent = certs[certs.length - 1];
            for (int i = certs.length - 1; i >= 0; i--) {
                X509Certificate cert = certs[i];

                // Verify that the certificate has not expired.

                cert.checkValidity();
                cert.verify(parent.getPublicKey());
                parent = cert;

                try {
                    certsStatus[i] = fetchStatus(String.valueOf(cert.getSerialNumber()));
                } catch (IOException e) {
                    throw new IOException("Unable to fetch certificate status. Check connectivity.", e);
                }

            } // for


            byte[] googleRootCaPubKey = Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY);
            if (Arrays.equals(
                    googleRootCaPubKey,
                    certs[certs.length - 1].getPublicKey().getEncoded())) {

                certGoogle = true;
            }
            else {
                certGoogle = false;
            }

            if(certsStatus[0] && certsStatus[1] && certsStatus[2] && certsStatus[3] && certGoogle)
                return true;
            else
                return false;
        }


        private boolean fetchStatus(String serialNumber) throws IOException {
            final String STATUS_URL = "https://android.googleapis.com/attestation/status";
            final String CACHE_PATH = "httpcache";
            final Cache CACHE = new Cache(new File(CACHE_PATH), 10 * 1024 * 1024);
            final OkHttpClient CLIENT = new OkHttpClient.Builder().cache(CACHE).build();
            URL url;

            try {
                url = new URL(STATUS_URL);
            } catch (MalformedURLException e) {
                throw new IllegalStateException(e);
            }

            Request request = new Request.Builder()
                    .url(url)
                    .build();

            try {
                Response response = CLIENT.newCall(request).execute();
                if(response.isSuccessful()){
                    String responseBody = response.body().string();
                    if (responseBody.contains('"' + serialNumber + '"')){
                        return false;
                    }
                    else
                        return true;
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }

            return false;
        }

        public void stopServer(){
            serverRunning = false;
            new Thread(new Runnable() {
                @Override
                public void run() {

                    // if it is opened (!= null)
                    if(serverSocket != null){
                        try {
                            serverSocket.close();

                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    tvStatus.setText("Server stopped");
                                }
                            });

                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }).start();
        }
    }   // serverThread
} // main