package com.sshfleet.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.webkit.CookieManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final String PREFS_NAME = "ssh_fleet_prefs";
    private static final String KEY_HUB_URL = "hub_url";

    private WebView webView;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Window win = getWindow();
        win.setStatusBarColor(Color.parseColor("#0b0f19"));
        win.setNavigationBarColor(Color.parseColor("#0b0f19"));

        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#0b0f19"));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#0b0f19"));
        setupWebView(webView);
        root.addView(webView, new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ));

        // Subtle floating settings pill in top-right so user can switch Hub / CF Access URL anytime.
        TextView gearBtn = new TextView(this);
        gearBtn.setText("⚙ Hub");
        gearBtn.setTextColor(Color.parseColor("#94a3b8"));
        gearBtn.setTextSize(11f);
        gearBtn.setPadding(20, 10, 20, 10);
        GradientDrawable pill = new GradientDrawable();
        pill.setColor(Color.argb(175, 19, 26, 42));
        pill.setCornerRadius(32f);
        pill.setStroke(2, Color.parseColor("#283552"));
        gearBtn.setBackground(pill);
        gearBtn.setOnClickListener(v -> promptHubUrl(false));

        FrameLayout.LayoutParams btnParams = new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM | Gravity.END
        );
        btnParams.setMargins(0, 0, 28, 120);
        root.addView(gearBtn, btnParams);

        setContentView(root);

        String savedUrl = prefs.getString(KEY_HUB_URL, "");
        if (savedUrl == null || savedUrl.trim().isEmpty()) {
            promptHubUrl(true);
        } else {
            webView.loadUrl(savedUrl);
        }
    }

    private void setupWebView(WebView wv) {
        CookieManager cm = CookieManager.getInstance();
        cm.setAcceptCookie(true);
        cm.setAcceptThirdPartyCookies(wv, true);

        WebSettings s = wv.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        s.setBuiltInZoomControls(false);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        }

        wv.setWebChromeClient(new WebChromeClient());
        wv.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                // Keep Cloudflare Access SSO / OTP / IdP redirects inside WebView so cookies stay shared.
                return false;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                CookieManager.getInstance().flush();
            }
        });
    }

    private void promptHubUrl(boolean required) {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        input.setHint("https://ssh.your-domain.com");
        String existing = prefs.getString(KEY_HUB_URL, "");
        if (existing != null && !existing.isEmpty()) {
            input.setText(existing);
        }

        AlertDialog.Builder b = new AlertDialog.Builder(this)
            .setTitle("SSH Fleet Hub / CF Access URL")
            .setMessage("Enter your Hub URL (e.g. https://ssh.domain.com or http://VPS_IP:8090):")
            .setView(input)
            .setCancelable(!required)
            .setPositiveButton("Connect", (d, w) -> {
                String url = input.getText().toString().trim();
                if (url.isEmpty()) {
                    Toast.makeText(this, "URL cannot be empty", Toast.LENGTH_SHORT).show();
                    if (required) promptHubUrl(true);
                    return;
                }
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    url = "https://" + url;
                }
                prefs.edit().putString(KEY_HUB_URL, url).apply();
                webView.loadUrl(url);
            });

        if (!required) {
            b.setNegativeButton("Cancel", null);
            b.setNeutralButton("Clear Cookies", (d, w) -> {
                CookieManager.getInstance().removeAllCookies(null);
                CookieManager.getInstance().flush();
                webView.reload();
                Toast.makeText(this, "Cookies cleared", Toast.LENGTH_SHORT).show();
            });
        }
        b.show();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        CookieManager.getInstance().flush();
    }
}
