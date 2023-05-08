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
using System.Security.Cryptography;
using System.IO;

namespace TCPServer
{
    public partial class ServerForm : Form
    {

        public ServerForm()
        {
            InitializeComponent();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        SimpleTcpServer server;
        private ECDiffieHellmanCng ecdhServer;
        private bool isClientPublicKeyRecive = false;
        private byte[] clientPublicKey;
        private byte[] serverPublicKey;
        private byte[] sharedSecretKeyS;

        private RSACryptoServiceProvider serverRSA;
        private byte[] serverPublicKeyRSA;
        private byte[] clientPublicKeyRSA;
        private byte[] connectedServerPublicKeys;

        private void button1_Click(object sender, EventArgs e)
        {
            server = new SimpleTcpServer(txtIP.Text);
            server.Events.ClientConnected += Events_ClientConnected;
            server.Events.ClientDisconnected += Events_ClientDisconnected;
            server.Events.DataReceived += Events_DataReceived;
            server.Start();
            txtInfo.Text += $"Starting...{Environment.NewLine}";
            btnStart.Enabled = false;
            btnSend.Enabled = true;

            
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            btnSend.Enabled = false;
            ecdhServer = new ECDiffieHellmanCng();
            ecdhServer.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdhServer.HashAlgorithm = CngAlgorithm.Sha256;
            serverRSA = new RSACryptoServiceProvider();

            //Przygotowanie pakietu kluczy do wysłania przez serwer
            string tempPublicKey = serverRSA.ToXmlString(false);
            serverPublicKeyRSA = Encoding.UTF8.GetBytes(tempPublicKey);
            serverPublicKey = ecdhServer.PublicKey.ToByteArray();
            connectedServerPublicKeys = new byte[serverPublicKey.Length + serverPublicKeyRSA.Length];
            Array.Copy(serverPublicKey, connectedServerPublicKeys, serverPublicKey.Length);
            Array.Copy(serverPublicKeyRSA, 0, connectedServerPublicKeys, serverPublicKey.Length, serverPublicKeyRSA.Length);
            


        }
        
        private void Events_DataReceived(object? sender, DataReceivedFromClientEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                if (!isClientPublicKeyRecive)
                {
                    //Otrzymywanie kluczy publicznych clienta
                    clientPublicKey = e.Data.Take(140).ToArray();
                    clientPublicKeyRSA = e.Data.Skip(140).ToArray();
                    isClientPublicKeyRecive = true;
                    //ustalanie klucza wspólnego do szyfrowania AES
                    ECDiffieHellmanPublicKey clientPublicKeyt = ECDiffieHellmanCngPublicKey.FromByteArray(clientPublicKey, CngKeyBlobFormat.EccPublicBlob);
                    sharedSecretKeyS = ecdhServer.DeriveKeyMaterial(clientPublicKeyt);

                    txtLog.Text += $"Dzielony klucz do kodowania AES: {Encoding.UTF8.GetString(sharedSecretKeyS)}{Environment.NewLine}";
                    txtLog.Text += $"Klucz publiczny RSA otrzymany od Klienta: {Encoding.UTF8.GetString(clientPublicKeyRSA)}{Environment.NewLine}";
                    txtLog.Text += $"Klucz publiczny RSA wysłany do Klienta: {Encoding.UTF8.GetString(serverPublicKeyRSA)}{Environment.NewLine}";
                }
                else
                {
                    //Rozdzielenie wiadomości na skrót i wiadomość
                    byte[] encryptedHash = e.Data.Take(128).ToArray();
                    byte[] encryptedMessage = e.Data.Skip(128).ToArray();

                    //Odszyfrowanie wiadomości
                    string message = DecryptMessage(encryptedMessage, sharedSecretKeyS);

                    //Odszyfrowywanie skrótu kluczem prywatnym
                    byte[] decryptedHash = serverRSA.Decrypt(encryptedHash, true);

                    //Stworzenie skrótu z ostrzymanej wiadomości
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    SHA256 sha256 = SHA256.Create();
                    byte[] hash = sha256.ComputeHash(messageBytes);

                    //Porównywanie otrzymanego skrótu z tym wygenerowanym z tekstu
                    if(Encoding.UTF8.GetString(decryptedHash)== Encoding.UTF8.GetString(hash))
                    {
                        //Wyświetlanie wiadomości Serwerowi
                        txtInfo.Text += $"{e.IpPort}: {message}{Environment.NewLine}";
                    }
                    else
                    {
                        txtLog.Text += $"Skrót otrzymany od klienta: {Encoding.UTF8.GetString(decryptedHash)}{Environment.NewLine}";
                        txtLog.Text += $"Skrót otrzymany po stworzeniu z wiadomości: {Encoding.UTF8.GetString(hash)}{Environment.NewLine}";
                    }
                }
            });
        }

        private void Events_ClientDisconnected(object? sender, ClientDisconnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"{e.IpPort} disconnected.{Environment.NewLine}";
                lstClientIP.Items.Remove(e.IpPort);
            });
        }

        private void Events_ClientConnected(object? sender, ClientConnectedEventArgs e)
        {
            this.Invoke((MethodInvoker)delegate
            {
                txtInfo.Text += $"{e.IpPort} connected.{Environment.NewLine}";

                //Wysłanie pakietu kluczy publicznych przy połączeniu
                server.Send(e.IpPort, connectedServerPublicKeys);
                
                lstClientIP.Items.Add(e.IpPort);
                
                

            });
            
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (server.IsListening)
            {
                if(!string.IsNullOrEmpty(txtxMessage.Text) && lstClientIP.SelectedItem != null)
                {
                    //Tworzenie skrótu SHU-256 wiadomości
                    string message = txtxMessage.Text;
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    SHA256 sha256 = SHA256.Create();
                    byte[] hash = sha256.ComputeHash(messageBytes);
                    //Szyfrowanie skrótu za pomocą klucza publicznego adresata
                    string publicKeyXml = Encoding.UTF8.GetString(clientPublicKeyRSA);
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(publicKeyXml);
                    byte[] encryptedHash = rsa.Encrypt(hash, true);
                    //Szyfrowanie wiadomości za pomocą współdzielonego klucza
                    byte[] encryptedMessage = EncryptMessage(message, sharedSecretKeyS);
                    //Łączenie wiadomości z zaszyfrowanym skrótem
                    byte[] messageForSend = new byte[encryptedHash.Length + encryptedMessage.Length];
                    Array.Copy(encryptedHash, messageForSend, encryptedHash.Length);
                    Array.Copy(encryptedMessage, 0, messageForSend, encryptedHash.Length, encryptedMessage.Length);
                    //Wysyłanie wiadomości
                    server.Send(lstClientIP.SelectedItem.ToString(), messageForSend);
                    // Wyświetlanie wiadomości wysłanej przez serwer i wymazywanie miejsca do wpisywania wiadomości
                    txtInfo.Text += $"Server: {txtxMessage.Text}{Environment.NewLine}";
                    txtxMessage.Text = String.Empty;
                }
            }
        }

        private void txtInfo_TextChanged(object sender, EventArgs e)
        {

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
