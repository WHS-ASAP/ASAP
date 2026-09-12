package com.example.asap;

// STATIC-ONLY FIXTURE: not a buildable app, no payloads, no real credentials.
import android.database.sqlite.SQLiteOpenHelper;
import android.content.Intent;
import android.webkit.WebView;

public class ReviewActivity {
    private static final String API_SECRET = "DEMO_ONLY_CONSTANT_2026_ASAP";

    public void reviewQuery() {
        String queryValue = getIntent().getStringExtra("query");
        String queryText = "SELECT title FROM notes WHERE owner = '" + queryValue + "'";
        database.rawQuery(queryText, null);
        // A safe call must not hide the preceding independent review candidate.
        database.rawQuery("SELECT title FROM notes WHERE owner = ?", new String[]{queryValue});
    }

    public void reviewWebContent() {
        String incomingUrl = getIntent().getDataString();
        webView.loadUrl(incomingUrl);
        webView.addJavascriptInterface(bridge, "DemoBridge");
        webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
        WebView.setWebContentsDebuggingEnabled(true);
        webView.getSettings().setMixedContentMode(0);
    }

    public void reviewIntentBoundary() {
        Intent candidate = getIntent().getParcelableExtra("destination");
        startActivity(candidate);
    }

    public void reviewCrypto() {
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        MessageDigest.getInstance("MD5");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    }

    public void reviewLogging(String accessToken) {
        Log.d("demo", "Access token: " + accessToken);
        Log.i("demo", "User requested password reset");
    }
}
