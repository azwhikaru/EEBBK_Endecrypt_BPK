package io.hikaru.endecrypt;

import android.app.Activity;
import android.content.pm.*;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main_layout);

        Button checkButton = (Button) findViewById(R.id.button_check);
        Button decodeButton = (Button) findViewById(R.id.button_decode);
        Button checkMd5Button = (Button) findViewById(R.id.button_checkmd5);
        EditText editPath = (EditText) findViewById(R.id.edittext_path);
        EditText decodePath = (EditText) findViewById(R.id.decodebpk_path);
        EditText checkMd5Path = (EditText) findViewById(R.id.checkmd5_path);

        checkButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String filePath = editPath.getText().toString();
                if(filePath == ""){
                    Toast.makeText(MainActivity.this, "Path not found", Toast.LENGTH_SHORT).show();
                    return;
                }
                String callbackMsg = Endecrypt.checkApkIfEncode(filePath);
                Toast.makeText(MainActivity.this, callbackMsg, Toast.LENGTH_SHORT).show();
            }
        });

        decodeButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String filePath = decodePath.getText().toString();
                if(filePath == ""){
                    Toast.makeText(MainActivity.this, "Path not found", Toast.LENGTH_SHORT).show();
                    return;
                }
                String callbackMsg = Endecrypt.decodeApkFile(filePath);
                Toast.makeText(MainActivity.this, callbackMsg, Toast.LENGTH_SHORT).show();
            }
        });

        checkMd5Button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String filePath = checkMd5Path.getText().toString();
                if(filePath.equals("")){
                    Toast.makeText(MainActivity.this, "Package not found", Toast.LENGTH_SHORT).show();
                    return;
                }
                String callbackMsg = Endecrypt.checkIsMd5(getApplicationContext(), filePath);
                Toast.makeText(MainActivity.this, callbackMsg, Toast.LENGTH_SHORT).show();
            }
        });
    }
}