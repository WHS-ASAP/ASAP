package com.example.asap;

// Negative cases in a shared fixture: there must be no security finding for this file.
public class SafeExamples {
    public void query(String value) {
        database.rawQuery("SELECT name FROM demo WHERE id = ?", new String[]{value});
        Cipher.getInstance("AES/GCM/NoPadding");
        webView.getSettings().setAllowFileAccess(false);
        Log.i("demo", "password field displayed");
        String harmless = "Cipher.getInstance(\"DES\")";
    }
}
