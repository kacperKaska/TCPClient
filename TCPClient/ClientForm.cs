using SimpleTcp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace TCPClient
{
    public partial class ClientForm : Form
    {
        public ClientForm()
        {
            InitializeComponent();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        SimpleTcpClient client;
        

        private void btnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                client = new(txtIP.Text);
                client.Events.Connected += Events_Connected;
                client.Events.DataReceived += Events_DataReceived;
                client.Events.Disconnected += Events_Disconnected;
                client.Connect();
                btnSend.Enabled = true;
                btnConnect.Enabled = false;

                //wysyłanie pakietu kluczy publicznych do serwera
                client.Send(connectedClientPublicKeys);

                while(serverPublicKeyBytes == null)
                {
                    Application.DoEvents();
                }
                ECDiffieHellmanPublicKey serverPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(serverPublicKeyBytes, CngKeyBlobFormat.EccPublicBlob);
                sharedSecretKey = ecdhClient.DeriveKeyMaterial(serverPublicKey);
                

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Message", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (client.IsConnected)
            {
                if (!string.IsNullOrEmpty(txtxMessage.Text))
                {
                    //Tworzenie skrótu SHU-256 wiadomości
                    string message = txtxMessage.Text;
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    SHA256 sha256 = SHA256.Create();
                    byte[] hash = sha256.ComputeHash(messageBytes);

                    //Szyfrowanie skrótu za pomocą klucza publicznego adresata
                    string publicKeyXml = Encoding.UTF8.GetString(serverPublicKeyRSA);
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(publicKeyXml);
                    byte[] encryptedHash = rsa.Encrypt(hash, true);

                    //Szyfrowanie wiadomości za pomocą współdzielonego klucza
                    byte[] encryptedMessage = EncryptMessage(message, sharedSecretKey);

                    //Łączenie wiadomości z zaszyfrowanym skrótem
                    byte[] messageForSend = new byte[encryptedHash.Length + encryptedMessage.Length];
                    Array.Copy(encryptedHash, messageForSend, encryptedHash.Length);
                    Array.Copy(encryptedMessage, 0, messageForSend, encryptedHash.Length, encryptedMessage.Length);

                    //Wysyłanie wiadomości
                    client.Send(messageForSend);

                    // Wyświetlanie wiadomości wysłanej przez klienta i wymazywanie miejsca do wpisywania wiadomości
                    txtInfo.Text += $"Me: {message}{Environment.NewLine}";
                    txtxMessage.Text = string.Empty;
                }
            }
        }

        private ECDiffieHellmanCng ecdhClient;
        private byte[] clientPublicKey;
        private byte[] sharedSecretKey;
        private bool isServerPublicKeyReceived = false;

        private RSACryptoServiceProvider clientRSA;
        private byte[] serverPublicKeyRSA;
        private byte[] clientPublicKeyRSA;
        private byte[] connectedClientPublicKeys;


        private void Form1_Load(object sender, EventArgs e)
        {
            //Generowanie klucza publicznego i prywatnego klienta DH
            ecdhClient = new ECDiffieHellmanCng();
            ecdhClient.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdhClient.HashAlgorithm = CngAlgorithm.Sha256;
            clientRSA = new RSACryptoServiceProvider();
            //Przygotowywanie pakietu kluczy publicznych do wysłania przez klienta
            string tempPublicKey = clientRSA.ToXmlString(false);
            clientPublicKeyRSA = Encoding.UTF8.GetBytes(tempPublicKey);
            clientPublicKey = ecdhClient.PublicKey.ToByteArray();
            connectedClientPublicKeys = new byte[clientPublicKey.Length + clientPublicKeyRSA.Length];
            Array.Copy(clientPublicKey, connectedClientPublicKeys, clientPublicKey.Length);
            Array.Copy(clientPublicKeyRSA, 0, connectedClientPublicKeys, clientPublicKey.Length, clientPublicKeyRSA.Length);

            btnSend.Enabled = false;
        }

        private void Events_Disconnected(object? sender, EventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server disconnected.{Environment.NewLine}";
            });
        }

        private bool isServerPublicKeySended = false;
        private byte[] serverPublicKeyBytes;
        private void Events_DataReceived(object? sender, DataReceivedFromServerEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (!isServerPublicKeySended)
                {
                    //Otrzymywanie serwerowych kluczy publicznych
                    serverPublicKeyBytes = e.Data.Take(140).ToArray();
                    serverPublicKeyRSA = e.Data.Skip(140).ToArray();
                    isServerPublicKeySended = true;
                    //ustalanie klucza do szyfrowania AES
                    ECDiffieHellmanPublicKey serverPublicKeyt = ECDiffieHellmanCngPublicKey.FromByteArray(serverPublicKeyBytes, CngKeyBlobFormat.EccPublicBlob);
                    sharedSecretKey = ecdhClient.DeriveKeyMaterial(serverPublicKeyt);

                    txtLog.Text += $"Dzielony klucz do kodowania AES: {Encoding.UTF8.GetString(sharedSecretKey)}{Environment.NewLine}";
                    txtLog.Text += $"Klucz publiczny RSA otrzymany od Serwera: {Encoding.UTF8.GetString(serverPublicKeyRSA)}{Environment.NewLine}";
                    txtLog.Text += $"Klucz publiczny RSA wysłany do Serwera: {Encoding.UTF8.GetString(clientPublicKeyRSA)}{Environment.NewLine}";
                }
                else
                {
                    //Rozdzielenie wiadomości na skrót i wiadomość
                    byte[] encryptedHash = e.Data.Take(128).ToArray();
                    byte[] encryptedMessage = e.Data.Skip(128).ToArray();
                    //Odszyfrowanie wiadomości
                    string message = DecryptMessage(encryptedMessage, sharedSecretKey);
                    //Odszyfrowywanie skrótu kluczem prywatnym
                    byte[] decryptedHash = clientRSA.Decrypt(encryptedHash, true);
                    //Stworzenie skrótu z ostrzymanej wiadomości
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    SHA256 sha256 = SHA256.Create();
                    byte[] hash = sha256.ComputeHash(messageBytes);
                    //Porównywanie otrzymanego skrótu z tym wygenerowanym z tekstu
                    if (Encoding.UTF8.GetString(decryptedHash) == Encoding.UTF8.GetString(hash))
                    {
                        //Wyświetlanie wiadomości Serwerowi
                        txtInfo.Text += $"Serwer: {message}{Environment.NewLine}";
                    }
                    else
                    {
                        txtLog.Text += $"Skrót otrzymany od Serwera: {Encoding.UTF8.GetString(decryptedHash)}{Environment.NewLine}";
                        txtLog.Text += $"Skrót otrzymany po stworzeniu z wiadomości: {Encoding.UTF8.GetString(hash)}{Environment.NewLine}";
                    }
                }
            });
        }

        private void Events_Connected(object? sender, EventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"Server connected. {Environment.NewLine}";
            });
        }

        public static byte[] EncryptMessage(string message, byte[] key)
        {
            byte[] iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }

            byte[] encryptedMessage;
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(message);
                        }
                        encryptedMessage = msEncrypt.ToArray();
                    }
                }
            }

            byte[] ivAndEncryptedMessage = new byte[iv.Length + encryptedMessage.Length];
            Array.Copy(iv, ivAndEncryptedMessage, iv.Length);
            Array.Copy(encryptedMessage, 0, ivAndEncryptedMessage, iv.Length, encryptedMessage.Length);
            return ivAndEncryptedMessage;
        }
        public static string DecryptMessage(byte[] ivAndEncryptedMessage, byte[] key)
        {
            // Wydobycie IV
            byte[] iv = ivAndEncryptedMessage.Take(16).ToArray();

            // Wydobycie zaszyfrowanej wiadomości
            byte[] encryptedMessage = ivAndEncryptedMessage.Skip(16).ToArray();

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                    }

                    byte[] decryptedMessage = ms.ToArray();
                    return Encoding.UTF8.GetString(decryptedMessage);
                }
            }
        }

    }
}
