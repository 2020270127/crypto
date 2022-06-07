#include <stdint.h>
#include <stdio.h>
#include <arduino.h>

#define PIN_TRIGG 8
#define PIN_NUMBER 4
#define BAUD_RATE 230400

uint32_t count[16];

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AES

#define mulx(t) ((t << 1) & 0xff) ^ ((t & 0x80) ? 0x1b : 0)
#define mixcolumns(t1, t2, t3, t4) mulx(t1) ^ (mulx(t2) ^ t2) ^ t3 ^ t4

unsigned char SBox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x1, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x4, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x5, 0x9a, 0x7, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x9, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x0, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x2, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0xc, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0xb, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0xe, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0xd, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0xf, 0xb0, 0x54, 0xbb, 0x16
};

void key_generate(unsigned char *key, unsigned char(*round_key)[16]) {
  unsigned char rcon[11] = { 0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
  unsigned char G[4];
  unsigned char i;

  round_key[0][0] = key[0]; round_key[0][1] = key[1]; round_key[0][2] = key[2]; round_key[0][3] = key[3];
  round_key[0][4] = key[4]; round_key[0][5] = key[5]; round_key[0][6] = key[6]; round_key[0][7] = key[7];
  round_key[0][8] = key[8]; round_key[0][9] = key[9]; round_key[0][10] = key[10]; round_key[0][11] = key[11];
  round_key[0][12] = key[12]; round_key[0][13] = key[13]; round_key[0][14] = key[14]; round_key[0][15] = key[15];

  for (i = 1; i < 11; i++) {
    G[0] = SBox[round_key[i - 1][13]] ^ rcon[i]; G[1] = SBox[round_key[i - 1][14]]; G[2] = SBox[round_key[i - 1][15]]; G[3] = SBox[round_key[i - 1][12]];
    
    round_key[i][0] = round_key[i - 1][0] ^ G[0]; round_key[i][1] = round_key[i - 1][1] ^ G[1]; round_key[i][2] = round_key[i - 1][2] ^ G[2]; round_key[i][3] = round_key[i - 1][3] ^ G[3];
    round_key[i][4] = round_key[i - 1][4] ^ round_key[i][0]; round_key[i][5] = round_key[i - 1][5] ^ round_key[i][1]; round_key[i][6] = round_key[i - 1][6] ^ round_key[i][2]; round_key[i][7] = round_key[i - 1][7] ^ round_key[i][3];
    round_key[i][8] = round_key[i - 1][8] ^ round_key[i][4]; round_key[i][9] = round_key[i - 1][9] ^ round_key[i][5]; round_key[i][10] = round_key[i - 1][10] ^ round_key[i][6]; round_key[i][11] = round_key[i - 1][11] ^ round_key[i][7];
    round_key[i][12] = round_key[i - 1][12] ^ round_key[i][8]; round_key[i][13] = round_key[i - 1][13] ^ round_key[i][9]; round_key[i][14] = round_key[i - 1][14] ^ round_key[i][10]; round_key[i][15] = round_key[i - 1][15] ^ round_key[i][11];
  }
}

void AES_128(unsigned char *ciphertext, unsigned char *plaintext, unsigned char (*round_key)[16]) {
  unsigned char round, inter_val[16], Minter_val[16];

  //Round 0
  //digitalWrite(PIN_TRIGG, HIGH);
  inter_val[0] = plaintext[0] ^ round_key[0][0]; inter_val[1] = plaintext[1] ^ round_key[0][1]; inter_val[2] = plaintext[2] ^ round_key[0][2]; inter_val[3] = plaintext[3] ^ round_key[0][3];
  inter_val[4] = plaintext[4] ^ round_key[0][4]; inter_val[5] = plaintext[5] ^ round_key[0][5]; inter_val[6] = plaintext[6] ^ round_key[0][6]; inter_val[7] = plaintext[7] ^ round_key[0][7];
  inter_val[8] = plaintext[8] ^ round_key[0][8]; inter_val[9] = plaintext[9] ^ round_key[0][9]; inter_val[10] = plaintext[10] ^ round_key[0][10]; inter_val[11] = plaintext[11] ^ round_key[0][11];
  inter_val[12] = plaintext[12] ^ round_key[0][12]; inter_val[13] = plaintext[13] ^ round_key[0][13]; inter_val[14] = plaintext[14] ^ round_key[0][14]; inter_val[15] = plaintext[15] ^ round_key[0][15];

  //Round function
  for (round = 1; round < 10; round++) {
    //SubBytes
    inter_val[0] = SBox[inter_val[0]]; inter_val[1] = SBox[inter_val[1]]; inter_val[2] = SBox[inter_val[2]]; inter_val[3] = SBox[inter_val[3]];
    inter_val[4] = SBox[inter_val[4]]; inter_val[5] = SBox[inter_val[5]]; inter_val[6] = SBox[inter_val[6]]; inter_val[7] = SBox[inter_val[7]];
    inter_val[8] = SBox[inter_val[8]]; inter_val[9] = SBox[inter_val[9]]; inter_val[10] = SBox[inter_val[10]]; inter_val[11] = SBox[inter_val[11]];
    inter_val[12] = SBox[inter_val[12]]; inter_val[13] = SBox[inter_val[13]]; inter_val[14] = SBox[inter_val[14]]; inter_val[15] = SBox[inter_val[15]];
        
    //ShiftRows
    Minter_val[0] = inter_val[0]; Minter_val[1] = inter_val[5]; Minter_val[2] = inter_val[10]; Minter_val[3] = inter_val[15];
    Minter_val[4] = inter_val[4]; Minter_val[5] = inter_val[9]; Minter_val[6] = inter_val[14]; Minter_val[7] = inter_val[3];
    Minter_val[8] = inter_val[8]; Minter_val[9] = inter_val[13]; Minter_val[10] = inter_val[2]; Minter_val[11] = inter_val[7];
    Minter_val[12] = inter_val[12]; Minter_val[13] = inter_val[1]; Minter_val[14] = inter_val[6]; Minter_val[15] = inter_val[11];

    //MixColumns
    inter_val[0] = mixcolumns(Minter_val[0], Minter_val[1], Minter_val[2], Minter_val[3]);
    inter_val[1] = mixcolumns(Minter_val[1], Minter_val[2], Minter_val[3], Minter_val[0]);
    inter_val[2] = mixcolumns(Minter_val[2], Minter_val[3], Minter_val[0], Minter_val[1]);
    inter_val[3] = mixcolumns(Minter_val[3], Minter_val[0], Minter_val[1], Minter_val[2]);

    inter_val[4] = mixcolumns(Minter_val[4], Minter_val[5], Minter_val[6], Minter_val[7]);
    inter_val[5] = mixcolumns(Minter_val[5], Minter_val[6], Minter_val[7], Minter_val[4]);
    inter_val[6] = mixcolumns(Minter_val[6], Minter_val[7], Minter_val[4], Minter_val[5]);
    inter_val[7] = mixcolumns(Minter_val[7], Minter_val[4], Minter_val[5], Minter_val[6]);

    inter_val[8] = mixcolumns(Minter_val[8], Minter_val[9], Minter_val[10], Minter_val[11]);
    inter_val[9] = mixcolumns(Minter_val[9], Minter_val[10], Minter_val[11], Minter_val[8]);
    inter_val[10] = mixcolumns(Minter_val[10], Minter_val[11], Minter_val[8], Minter_val[9]);
    inter_val[11] = mixcolumns(Minter_val[11], Minter_val[8], Minter_val[9], Minter_val[10]);

    inter_val[12] = mixcolumns(Minter_val[12], Minter_val[13], Minter_val[14], Minter_val[15]);
    inter_val[13] = mixcolumns(Minter_val[13], Minter_val[14], Minter_val[15], Minter_val[12]);
    inter_val[14] = mixcolumns(Minter_val[14], Minter_val[15], Minter_val[12], Minter_val[13]);
    inter_val[15] = mixcolumns(Minter_val[15], Minter_val[12], Minter_val[13], Minter_val[14]);

    //AddRoundKey
    inter_val[0] = inter_val[0] ^ round_key[round][0]; inter_val[1] = inter_val[1] ^ round_key[round][1]; inter_val[2] = inter_val[2] ^ round_key[round][2]; inter_val[3] = inter_val[3] ^ round_key[round][3];
    inter_val[4] = inter_val[4] ^ round_key[round][4]; inter_val[5] = inter_val[5] ^ round_key[round][5]; inter_val[6] = inter_val[6] ^ round_key[round][6]; inter_val[7] = inter_val[7] ^ round_key[round][7];
    inter_val[8] = inter_val[8] ^ round_key[round][8]; inter_val[9] = inter_val[9] ^ round_key[round][9]; inter_val[10] = inter_val[10] ^ round_key[round][10]; inter_val[11] = inter_val[11] ^ round_key[round][11];
    inter_val[12] = inter_val[12] ^ round_key[round][12]; inter_val[13] = inter_val[13] ^ round_key[round][13]; inter_val[14] = inter_val[14] ^ round_key[round][14]; inter_val[15] = inter_val[15] ^ round_key[round][15];
     
    //if (round == 1) digitalWrite(PIN_TRIGG, LOW);
  }

  //Round 10
  inter_val[0] = SBox[inter_val[0]]; inter_val[1] = SBox[inter_val[1]]; inter_val[2] = SBox[inter_val[2]]; inter_val[3] = SBox[inter_val[3]];
  inter_val[4] = SBox[inter_val[4]]; inter_val[5] = SBox[inter_val[5]]; inter_val[6] = SBox[inter_val[6]]; inter_val[7] = SBox[inter_val[7]];
  inter_val[8] = SBox[inter_val[8]]; inter_val[9] = SBox[inter_val[9]]; inter_val[10] = SBox[inter_val[10]]; inter_val[11] = SBox[inter_val[11]];
  inter_val[12] = SBox[inter_val[12]]; inter_val[13] = SBox[inter_val[13]]; inter_val[14] = SBox[inter_val[14]]; inter_val[15] = SBox[inter_val[15]];

  Minter_val[0] = inter_val[0]; Minter_val[1] = inter_val[5]; Minter_val[2] = inter_val[10]; Minter_val[3] = inter_val[15];
  Minter_val[4] = inter_val[4]; Minter_val[5] = inter_val[9]; Minter_val[6] = inter_val[14]; Minter_val[7] = inter_val[3];
  Minter_val[8] = inter_val[8]; Minter_val[9] = inter_val[13]; Minter_val[10] = inter_val[2]; Minter_val[11] = inter_val[7];
  Minter_val[12] = inter_val[12]; Minter_val[13] = inter_val[1]; Minter_val[14] = inter_val[6]; Minter_val[15] = inter_val[11];

  ciphertext[0] = Minter_val[0] ^ round_key[round][0]; ciphertext[1] = Minter_val[1] ^ round_key[round][1]; ciphertext[2] = Minter_val[2] ^ round_key[round][2]; ciphertext[3] = Minter_val[3] ^ round_key[round][3];
  ciphertext[4] = Minter_val[4] ^ round_key[round][4]; ciphertext[5] = Minter_val[5] ^ round_key[round][5]; ciphertext[6] = Minter_val[6] ^ round_key[round][6]; ciphertext[7] = Minter_val[7] ^ round_key[round][7];
  ciphertext[8] = Minter_val[8] ^ round_key[round][8]; ciphertext[9] = Minter_val[9] ^ round_key[round][9]; ciphertext[10] = Minter_val[10] ^ round_key[round][10]; ciphertext[11] = Minter_val[11] ^ round_key[round][11];
  ciphertext[12] = Minter_val[12] ^ round_key[round][12]; ciphertext[13] = Minter_val[13] ^ round_key[round][13]; ciphertext[14] = Minter_val[14] ^ round_key[round][14]; ciphertext[15] = Minter_val[15] ^ round_key[round][15];
  //digitalWrite(PIN_TRIGG, LOW);
}

unsigned char round_key[11][16];

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Padding(uint8_t *input, const uint32_t *count, const uint8_t temp, const uint8_t humi){
  input[0] = (count[0]) & 0xFF;
  input[1] = (count[1]) & 0xFF;
  input[2] = (count[2])  & 0xFF;
  input[3] = (count[3])  & 0xFF;
  input[4] = (count[4]) & 0xFF;
  input[5] = (count[5]) & 0xFF;
  input[6] = (count[6])  & 0xFF;
  input[7] = (count[7])  & 0xFF;
  input[8] = (count[8]) & 0xFF;
  input[9] = (count[9]) & 0xFF;
  input[10] = (count[10])  & 0xFF;
  input[11] = (count[11])  & 0xFF;
  input[12] = (count[12]) & 0xFF;
  input[13] = (count[13]) & 0xFF;
  input[14] = (count[14])  & 0xFF;
  input[15] = count[15] & 0xFF;
  input[16] = temp; 
  input[17] = humi;
}

void setup() {
  unsigned char key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  Serial.begin(BAUD_RATE);
  key_generate(key, round_key);
  pinMode(PIN_TRIGG, OUTPUT);
  digitalWrite(PIN_TRIGG, LOW);
}

void loop() {
  serialEvent();
}

void serialEvent() {
  uint8_t dht_status;
  uint8_t humi, temp;
  uint8_t input[18] = { 0, };
  uint8_t output[16];
  char		in;
  char 		ioc[8];

  while(Serial.available()) {
    in = (char) Serial.read();


    if(in == '1')
    {
      Padding(input, count, temp, humi);

 digitalWrite(PIN_TRIGG, HIGH);
      AES_128(output, input, round_key);
  digitalWrite(PIN_TRIGG, LOW);

      for(int i=0; i<16; i++){
        count[i]=rand();
      }
      
      for(int i=0; i<18; i++){
        sprintf(ioc, "%02X", input[i]);
        Serial.print(ioc);
      }
      Serial.print(" ");
      for(int i=0; i<16; i++){
        sprintf(ioc, "%02X", output[i]);
        Serial.print(ioc);
      }
      for(int i=16; i<18; i++){
        sprintf(ioc, "%02X", input[i]);
        Serial.print(ioc);
      }
      Serial.print("\n");
     
     }
  }
}
