package in.trinetra.validation.core;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Controlled validation UI for FraudShield/TRINETRA. */
public final class MainActivity extends Activity {
    private TextView status;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL); root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(48,72,48,48); root.setBackgroundColor(Color.rgb(248,250,252));
        TextView title = new TextView(this); title.setText("TRINETRA " + BuildConfig.VARIANT_NAME + " TEST");
        title.setTextSize(26f); title.setTextColor(Color.rgb(16,42,67)); title.setGravity(Gravity.CENTER); root.addView(title);
        TextView body = new TextView(this);
        body.setText("Controlled emulator-only validation app.\n\nPurpose: validate SMS → runtime observation → exact request-body correlation.\n\nSafety boundary:\n• Only DS-TEST-OTP-* markers are processed\n• Only http://10.0.2.2:8088/trinetra is contacted\n• No real credentials, contacts, files, persistence, or remote C2");
        body.setTextSize(16f); body.setTextColor(Color.rgb(71,85,105)); body.setPadding(0,36,0,36); root.addView(body);
        status = new TextView(this); status.setTextSize(16f); status.setTextColor(Color.rgb(19,138,91)); status.setGravity(Gravity.CENTER); root.addView(status);
        Button arm = new Button(this); arm.setText("ENABLE CONTROLLED SMS TEST"); arm.setOnClickListener(v -> requestSms());
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT); p.topMargin=28; root.addView(arm,p);
        TextView footer = new TextView(this); footer.setText("FraudShield DeceptiScope • TRINETRA • Analyze → Prove → Protect"); footer.setTextSize(13f); footer.setGravity(Gravity.CENTER); footer.setPadding(0,48,0,0); root.addView(footer);
        setContentView(root); refresh();
    }
    private void requestSms() {
        if (android.os.Build.VERSION.SDK_INT >= 23 && checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.RECEIVE_SMS},42);
        else refresh();
    }
    @Override public void onRequestPermissionsResult(int r,String[] p,int[] g){ super.onRequestPermissionsResult(r,p,g); refresh(); }
    private void refresh(){ boolean ok=android.os.Build.VERSION.SDK_INT<23||checkSelfPermission(Manifest.permission.RECEIVE_SMS)==PackageManager.PERMISSION_GRANTED; status.setText(ok?"ARMED: waiting for a DS-TEST-OTP-* marker":"NOT ARMED: grant SMS permission for the controlled test"); }
}
