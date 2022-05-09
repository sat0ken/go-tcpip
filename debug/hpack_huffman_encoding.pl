#!/usr/bin/perl

#A simple HPACK decoder for HTTP/2 Header Compressions
#More intented as a teaching exercise rather than something to use in real life
#Created for the Manning Book "HTTP/2 in Action"
#available at https://www.manning.com/books/http2-in-action and all good book stores
#This code is given in Chapter 8, listing 1

use strict;
use warnings;

# 変換する文字列をコマンドラインから読み取る
my ($input_string) = @ARGV;
 
if (not defined $input_string) {
  die "Need string\n";
}

#Set up and populate a has variable with all the huffman lookup values
#Note only printable values are used in this simple example
# ハッシュ変数を設定し、ハフマン符号化テーブルの値を入力する
my %hpack_huffman_table;

$hpack_huffman_table{' '} = '010100';
$hpack_huffman_table{'!'} = '1111111000';
$hpack_huffman_table{'\"'} = '1111111001';
$hpack_huffman_table{'#'} = '111111111010';
$hpack_huffman_table{'$'} = '1111111111001';
$hpack_huffman_table{'%'} = '010101';
$hpack_huffman_table{'&'} = '11111000';
$hpack_huffman_table{'\''} = '11111111010';
$hpack_huffman_table{'('} = '1111111010';
$hpack_huffman_table{')'} = '1111111011';
$hpack_huffman_table{'*'} = '11111001';
$hpack_huffman_table{'+'} = '11111111011';
$hpack_huffman_table{','} = '11111010';
$hpack_huffman_table{'-'} = '010110';
$hpack_huffman_table{'.'} = '010111';
$hpack_huffman_table{'/'} = '011000';
$hpack_huffman_table{'0'} = '00000';
$hpack_huffman_table{'1'} = '00001';
$hpack_huffman_table{'2'} = '00010';
$hpack_huffman_table{'3'} = '011001';
$hpack_huffman_table{'4'} = '011010';
$hpack_huffman_table{'5'} = '011011';
$hpack_huffman_table{'6'} = '011100';
$hpack_huffman_table{'7'} = '011101';
$hpack_huffman_table{'8'} = '011110';
$hpack_huffman_table{'9'} = '011111';
$hpack_huffman_table{':'} = '1011100';
$hpack_huffman_table{';'} = '11111011';
$hpack_huffman_table{'<'} = '111111111111100';
$hpack_huffman_table{'='} = '100000';
$hpack_huffman_table{'>'} = '111111111011';
$hpack_huffman_table{'?'} = '1111111100';
$hpack_huffman_table{'@'} = '1111111111010';
$hpack_huffman_table{'A'} = '100001';
$hpack_huffman_table{'B'} = '1011101';
$hpack_huffman_table{'C'} = '1011110';
$hpack_huffman_table{'D'} = '1011111';
$hpack_huffman_table{'E'} = '1100000';
$hpack_huffman_table{'F'} = '1100001';
$hpack_huffman_table{'G'} = '1100010';
$hpack_huffman_table{'H'} = '1100011';
$hpack_huffman_table{'I'} = '1100100';
$hpack_huffman_table{'J'} = '1100101';
$hpack_huffman_table{'K'} = '1100110';
$hpack_huffman_table{'L'} = '1100111';
$hpack_huffman_table{'M'} = '1101000';
$hpack_huffman_table{'N'} = '1101001';
$hpack_huffman_table{'O'} = '1101010';
$hpack_huffman_table{'P'} = '1101011';
$hpack_huffman_table{'Q'} = '1101100';
$hpack_huffman_table{'R'} = '1101101';
$hpack_huffman_table{'S'} = '1101110';
$hpack_huffman_table{'T'} = '1101111';
$hpack_huffman_table{'U'} = '1110000';
$hpack_huffman_table{'V'} = '1110001';
$hpack_huffman_table{'W'} = '1110010';
$hpack_huffman_table{'X'} = '11111100';
$hpack_huffman_table{'Y'} = '1110011';
$hpack_huffman_table{'Z'} = '11111101';
$hpack_huffman_table{'['} = '1111111111011';
$hpack_huffman_table{'\\'} = '1111111111111110000';
$hpack_huffman_table{']'} = '1111111111100';
$hpack_huffman_table{'^'} = '11111111111100';
$hpack_huffman_table{'_'} = '100010';
$hpack_huffman_table{'`'} = '111111111111101';
$hpack_huffman_table{'a'} = '00011';
$hpack_huffman_table{'b'} = '100011';
$hpack_huffman_table{'c'} = '00100';
$hpack_huffman_table{'d'} = '100100';
$hpack_huffman_table{'e'} = '00101';
$hpack_huffman_table{'f'} = '100101';
$hpack_huffman_table{'g'} = '100110';
$hpack_huffman_table{'h'} = '100111';
$hpack_huffman_table{'i'} = '00110';
$hpack_huffman_table{'j'} = '1110100';
$hpack_huffman_table{'k'} = '1110101';
$hpack_huffman_table{'l'} = '101000';
$hpack_huffman_table{'m'} = '101001';
$hpack_huffman_table{'n'} = '101010';
$hpack_huffman_table{'o'} = '00111';
$hpack_huffman_table{'p'} = '101011';
$hpack_huffman_table{'q'} = '1110110';
$hpack_huffman_table{'r'} = '101100';
$hpack_huffman_table{'s'} = '01000';
$hpack_huffman_table{'t'} = '01001';
$hpack_huffman_table{'u'} = '101101';
$hpack_huffman_table{'v'} = '1110111';
$hpack_huffman_table{'w'} = '1111000';
$hpack_huffman_table{'x'} = '1111001';
$hpack_huffman_table{'y'} = '1111010';
$hpack_huffman_table{'z'} = '1111011';
$hpack_huffman_table{'{'} = '111111111111110';
$hpack_huffman_table{'|'} = '11111111100';
$hpack_huffman_table{'}'} = '11111111111101';
$hpack_huffman_table{'~'} = '1111111111101';

#Set up a binary string variable
my $binary_string="";

#Split the input string by character
# 入力文字列を1文字ごとに分解
my @input_array = split(//, $input_string);

#For each inoput character lookup the string in the huffman hash table
#And add it to the binary_string variable.
# 1文字ずつに分解した文字をハフマン符号化テーブルを参照して検索
# 検索してヒットした結果のバイナリ文字列を変数に追加
foreach (@input_array) {
  $binary_string = $binary_string . $hpack_huffman_table{$_};
}

#Pad out the binary string to ensure it is divisble by 8
# バイナリ文字列をパディングして8、オクテットで割り切れるようにする
# 割り切れなかったら末尾に1を入れて埋める
while (length($binary_string) % 8 != 0) {
        $binary_string = $binary_string . "1";
};

#Calculate the length by diving by 8
# 8で割ってbyteの長さを計算
my $string_length = length($binary_string)/8;

#This simple implementation does not handle large strings
#(left as an exercise for the reader)
# 大きな文字列の処理は実装していない、読者の演習とする
if ($string_length > 127) {
        die "Error string length > 127 which is not handled by this program\n";
}

#Set the most significant bit (128) to indicate huffman encoding is used
#and include the length
#(again this simple version niavely assumes 7 bits for the length).
# 最上位ビット（128）を設定し長さを含めつつ、ハフマン符号化が使用されていることを示す
# ここでも単純に長さが7bitであることを想定している
printf("Huffman Encoding Flag + Length: %x\n",128+$string_length);

#Iterate though each 4-bit value and convert to hexidecimal
# 各4bit値を繰り返し処理して、16進数に変換
printf("Huffman Encoding Value        : ");
for(my $count=0;$count<length($binary_string);$count = $count + 4) {
        my $bin_value = substr($binary_string,$count,4);
        printf("%x",oct("0b" .$bin_value));
}
printf ("\n");

