package io.hikaru.endecrypt;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ChangedPackages;
import android.content.pm.FeatureInfo;
import android.content.pm.InstrumentationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PermissionGroupInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.SharedLibraryInfo;
import android.content.pm.VersionedPackage;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.UserHandle;
import android.util.Log;

import java.security.MessageDigest;
import javax.crypto.*;
import javax.crypto.spec.*;
import android.os.Environment;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.*;
import java.nio.channels.FileLock;
import java.util.List;

public class Endecrypt {

    public static String checkApkIfEncode(String apkAbsolutePath) {
        byte[] originBPKHeader = new byte[]{(byte) 66, (byte) 80, (byte) 75, (byte) 3};    //42 50 4B 03 BPK头部
        byte[] encodeBPKHeader = new byte[]{(byte) 35, (byte) 50, (byte) 40, (byte) 103};  //23 32 28 67 加密头部

        if(!isFileExists(apkAbsolutePath)){
            Log.e("checkApkIfEncode", "File is not exists...!");
            return "File not found";
        }

        FileInputStream fileInputStream = null;
        Log.d("checkApkIfEncode", "Start reading file: " + apkAbsolutePath);

        try {
            Log.d("checkApkIfEncode", "Reading file...");
            fileInputStream = new FileInputStream(apkAbsolutePath);
            byte[] buffer = new byte[4];
            fileInputStream.read(buffer);
            boolean isOriginBPKHeader = true;
            for (int i = 0; i < originBPKHeader.length; i++) {
                if (buffer[i] != originBPKHeader[i]) {
                    isOriginBPKHeader = false;
                    break;
                }
            }
            if (isOriginBPKHeader)
                return "No need decode BPK (内部应用)";
            for (int i = 0; i < encodeBPKHeader.length; i++)
                if (buffer[i] != encodeBPKHeader[i])
                    return "No need decode APK (外部应用)";
            return "Need decode BPK (加密应用)";
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("checkApkIfEncode", "Error while reading file!");
            return "Error: Error while reading file!";
        } finally {
            try {
                if (fileInputStream != null)
                    fileInputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static boolean isFileExists(String filePath) {
        File file = new File(filePath);
        if(file.exists()){
            return true;
        } else {
            return false;
        }
    }

    public static String getFileNameExceptExtendNameByFilePath(String filepath) {
        return filepath.substring(filepath.lastIndexOf("/") + 1, filepath.lastIndexOf("."));
    }

    public static String decodeApkFile(String apkAbsolutePath) {

        if(!isFileExists(apkAbsolutePath)){
            Log.e("decodeApkFile", "File not found, exiting...!");
            return("File not found");
        }

        byte[] xorCode = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();
        File file = new File(apkAbsolutePath);
        String outputPath = Environment.getExternalStorageDirectory() + "/Download/" + getFileNameExceptExtendNameByFilePath(apkAbsolutePath) + "-decode.apk";
        File outfile = new File(outputPath);
        int offset = 0;
        FileInputStream inputStream = null;
        FileOutputStream outputStream = null;
        FileLock fileLock = null;
        try {
            inputStream = new FileInputStream(file);
            outputStream = new FileOutputStream(outfile);
            fileLock = outputStream.getChannel().lock();
            byte[] buffer = new byte[1024];
            Log.d("decodeApkFile", "Start reading file...");
            while (true) {
                int len = inputStream.read(buffer);
                if (len == -1) {
                    break;
                }
                for (int i = 0; i < len; i++) {
                    buffer[i] = (byte) (buffer[i] ^ xorCode[offset % xorCode.length]);
                    offset++;
                }
                outputStream.write(buffer, 0, len);
            }
            outputStream.flush();
            return outputPath;
        } catch (Exception e) {
            e.printStackTrace();
            outfile.delete();
            return "Error while writing file";
        } finally {
            Log.d("decodeApkFile", "Successfully decoded the file, exiting...");
            try {
                if (inputStream != null)
                    inputStream.close();
                if (outputStream != null)
                    outputStream.close();
                if (fileLock != null)
                    fileLock.release();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static byte[] md5(String strSrc) {
        try {
            return MessageDigest.getInstance("MD5").digest(strSrc.getBytes("GBK"));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] getEnKey(String spKey) {
        byte[] desKey = null;
        try {
            byte[] desKey1 = md5(spKey);
            desKey = new byte[24];
            int i = 0;
            while (i < desKey1.length && i < 24) {
                desKey[i] = desKey1[i];
                i++;
            }
            if (i < 24) {
                desKey[i] = 0;
                int i2 = i + 1;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return desKey;
    }

    public static byte[] Encrypt(byte[] src, byte[] enKey) {
        try {
            SecretKey key = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(enKey));
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(1, key);
            return cipher.doFinal(src);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String toHexString(byte[] src) {
        StringBuilder build = new StringBuilder(src.length * 2);
        for (byte b : src) {
            if ((b & 255) < 16) {
                build.append("0");
            }
            build.append(Integer.toHexString(b & 255));
        }
        return build.toString();
    }

    public static String encrypt(String src, String spkey) {
        try {
            return toHexString(MessageDigest.getInstance("MD5").digest(Encrypt(src.getBytes("UTF-16LE"), getEnKey(spkey))));
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("encrypt", "An error occurred while generating MD5");
            return "Error while generating MD5";
        }
    }

    public static String checkIsMd5(Context context, String packageName) {
        ApplicationInfo ai;
        Bundle bundle;
        String metaData;
        String callbackMsg = Endecrypt.encrypt(packageName, "installer");

        try {
            ai = context.getPackageManager().getApplicationInfo(packageName, PackageManager.GET_META_DATA);
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("checkMd5Apk", "An error occurred while reading metadata");
            return "Error occurred while reading metadata";
        }
        if (!(ai == null || (bundle = ai.metaData) == null || (metaData = bundle.getString("bbkpackageinstaller")) == null || !callbackMsg.equals(metaData))) {
            return "is Md5 APK";
        }
        return "is Not Md5 APK";
    }
}
