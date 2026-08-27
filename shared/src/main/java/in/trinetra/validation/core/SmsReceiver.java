package in.trinetra.validation.core;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/** Defensive ground-truth receiver: ignores every SMS unless it contains DS-TEST-OTP-*. */
public final class SmsReceiver extends BroadcastReceiver {
    private static final String TAG="TRINETRA_VALIDATION";
    private static final Pattern TEST_MARKER=Pattern.compile("DS-TEST-OTP-[A-Za-z0-9_-]{4,64}");
    private static final String ENDPOINT="http://10.0.2.2:8088/trinetra";
    private static final MediaType JSON=MediaType.get("application/json; charset=utf-8");
    @Override public void onReceive(Context context, Intent intent) {
        if(!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;
        StringBuilder all=new StringBuilder(); SmsMessage[] messages=Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if(messages!=null) for(SmsMessage m:messages) if(m!=null&&m.getMessageBody()!=null) all.append(m.getMessageBody());
        Matcher match=TEST_MARKER.matcher(all.toString());
        if(!match.find()){ Log.i(TAG,"SMS ignored: no controlled TRINETRA marker present"); return; }
        String marker=match.group(); PendingResult pending=goAsync();
        new Thread(() -> { try { send(marker); } finally { pending.finish(); } },"trinetra-controlled-egress").start();
    }
    private void send(String marker) {
        OkHttpClient client=new OkHttpClient.Builder().connectTimeout(2,TimeUnit.SECONDS).readTimeout(2,TimeUnit.SECONDS).writeTimeout(2,TimeUnit.SECONDS).build();
        String json="{\"marker\":\""+marker+"\",\"source\":\"synthetic_sms\",\"variant\":\""+BuildConfig.VARIANT_NAME+"\"}";
        Request request=new Request.Builder().url(ENDPOINT).header("X-TRINETRA-Validation","controlled-emulator-only").post(RequestBody.create(json,JSON)).build();
        try(Response response=client.newCall(request).execute()){ Log.i(TAG,"Controlled marker sent to local emulator host; HTTP "+response.code()); }
        catch(IOException e){ Log.i(TAG,"Local collector unavailable after controlled request: "+e.getClass().getSimpleName()); }
    }
}
