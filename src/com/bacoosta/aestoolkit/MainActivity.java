package com.bacoosta.aestoolkit;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;

import group.pals.android.lib.ui.filechooser.FileChooserActivity;

import com.actionbarsherlock.app.SherlockActivity;
import com.actionbarsherlock.view.Menu;
import com.actionbarsherlock.view.MenuItem;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

public class MainActivity extends SherlockActivity {
	final static int _Encrypt = 0;
	final static int _Decrypt = 1;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		final Button enButton = (Button) findViewById(R.id.enButton);
		final Button deButton = (Button) findViewById(R.id.deButton);
		enButton.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				start(_Encrypt);
			}
		});
		deButton.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				start(_Decrypt);
			}
		});
	}

	private void start(int what) {
		Intent intent = new Intent(MainActivity.this, FileChooserActivity.class);
		intent.putExtra(FileChooserActivity._MultiSelection, true);
		startActivityForResult(intent, what);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getSupportMenuInflater().inflate(R.menu.activity_main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle item selection
		AlertDialog.Builder editalert;
		switch (item.getItemId()) {
		case R.id.menu_about:
			editalert = new AlertDialog.Builder(this);
			editalert.setTitle("About AES Toolkit");
			editalert.setMessage(R.string.about);
			editalert.setPositiveButton("OK", null);
			editalert.show();
			return true;
		case R.id.menu_license:
			editalert = new AlertDialog.Builder(this);
			editalert.setTitle("License");
			editalert.setMessage(R.string.license);
			editalert.setPositiveButton("OK", null);
			editalert.show();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	public static File getFile(Uri uri) {
		if (uri != null) {
			String filepath = uri.getPath();
			filepath = filepath.substring(11);
			if (filepath != null) {
				return new File(filepath);
			}
		}
		return null;
	}

	@Override
	protected void onActivityResult(final int requestCode, int resultCode,
			final Intent data) {
		if (resultCode == RESULT_OK) {
			final LinearLayout layout = new LinearLayout(this);
			final EditText input = new EditText(this);
			input.setInputType(InputType.TYPE_CLASS_TEXT
					| InputType.TYPE_TEXT_VARIATION_PASSWORD);
			input.setHint("Enter Password");
			final EditText input2 = new EditText(this);
			input2.setInputType(InputType.TYPE_CLASS_TEXT
					| InputType.TYPE_TEXT_VARIATION_PASSWORD);
			input2.setHint("Re-enter password");
			layout.setOrientation(LinearLayout.VERTICAL);
			layout.addView(input);
			if (requestCode == _Encrypt)
				layout.addView(input2);
			AlertDialog.Builder editalert = new AlertDialog.Builder(this);
			editalert
					.setTitle("Enter Password")
					.setView(layout)
					.setPositiveButton("OK",
							new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog,
										int which) {
									@SuppressWarnings("unchecked")
									ArrayList<Uri> files = (ArrayList<Uri>) data
											.getSerializableExtra(FileChooserActivity._Results);
									switch (requestCode) {
									case _Encrypt:
										if (input
												.getText()
												.toString()
												.equals(input2.getText()
														.toString()))
											new AESTask()
													.execute(input.getText()
															.toString()
															.toCharArray(),
															files, true);
										else
											Toast.makeText(MainActivity.this,
													"Passwords did not match",
													Toast.LENGTH_SHORT).show();
										break;
									case _Decrypt:
										new AESTask().execute(input.getText()
												.toString().toCharArray(),
												files, false);
										break;
									}
								}
							});
			editalert.show();
		}
	}

	GCMBlockCipher CipherInit(byte[] salt, byte[] iv, char[] password,
			boolean encrypt) {
		PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
		generator.init(
				PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password),
				salt, 2000);
		KeyParameter params = (KeyParameter) generator
				.generateDerivedParameters(256);
		GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());
		AEADParameters GCMparams = new AEADParameters(params, 128, iv, null);
		gcm.init(encrypt, GCMparams);
		return gcm;
	}

	private class AESTask extends AsyncTask<Object, Integer, Boolean> {
		ProgressDialog dialog;
		boolean abort = false;

		protected void onPreExecute() {
			dialog = new ProgressDialog(MainActivity.this);
			dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
				@Override
				public void onCancel(DialogInterface dialog) {
					abort = true;
				}
			});
			dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
			dialog.setButton(ProgressDialog.BUTTON_NEGATIVE, "Cancel",
					new DialogInterface.OnClickListener() {
						@Override
						public void onClick(DialogInterface dialog, int which) {
							dialog.cancel();
						}
					});
			dialog.setTitle("Operation in progress");
			dialog.show();
		}

		protected Boolean doInBackground(Object... params) {
			boolean worked = true;
			char[] password = (char[]) params[0];
			@SuppressWarnings("unchecked")
			ArrayList<Uri> files = (ArrayList<Uri>) params[1];
			int total = 0;
			for (Uri f : files) {
				total += getFile(f).length();
			}
			dialog.setMax(total);
			boolean encrypt = (Boolean) params[2];
			int blockSize = 524288; // Read/write block size, default is 512KB
			for (Uri myfile : files) {
				try {
					File file = getFile(myfile);
					BufferedInputStream fis = new BufferedInputStream(
							new FileInputStream(file), blockSize);
					BufferedOutputStream fos = new BufferedOutputStream(
							new FileOutputStream(file.getPath() + ".tmp"),
							blockSize);
					byte[] salt = new byte[16];
					byte[] iv = new byte[16];
					if (encrypt) {
						new SecureRandom().nextBytes(salt);
						new SecureRandom().nextBytes(iv);
						fos.write(iv, 0, 16);
						fos.write(salt, 0, 16);
					} else {
						fis.read(iv, 0, 16);
						fis.read(salt, 0, 16);
					}
					GCMBlockCipher gcm = CipherInit(salt, iv, password, encrypt);

					byte[] block = new byte[blockSize];
					int i, p;
					while ((i = fis.read(block)) != -1) {
						publishProgress(i);
						p = gcm.processBytes(block, 0, i, block, 0);
						fos.write(block, 0, p);
						if (abort)
							break;
					}
					// The rest of this verifies the integrity of the file, and
					// finishes writing
					try {
						p = gcm.doFinal(block, 0);
						fos.write(block, 0, p);
					} catch (InvalidCipherTextException e) {
						worked = false;
					}
					fis.close();
					fos.close();
					File tmp = new File(file.getPath() + ".tmp");
					if (worked && !abort) {
						file.delete();
						tmp.renameTo(file);
					} else {
						tmp.delete();
						return worked;
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return worked;
		}

		protected void onProgressUpdate(Integer... progress) {
			dialog.incrementProgressBy(progress[0]);
		}

		protected void onPostExecute(Boolean result) {
			if (abort)
				Toast.makeText(MainActivity.this, "Operation aborted!",
						Toast.LENGTH_SHORT).show();
			else if (result)
				Toast.makeText(MainActivity.this, "Done!", Toast.LENGTH_SHORT)
						.show();
			else
				Toast.makeText(MainActivity.this, "Incorrect key!",
						Toast.LENGTH_SHORT).show();
			dialog.dismiss();
		}
	}
}
