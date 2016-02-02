

[Program 4]
[Description]
There is one java file and the 4 plaintext/4 key test files.

So my program took in the text and cipherKey and put it on a 2d array.
Then I took the CipherKey and expanded it to the the necessary length.

The key expansion took the last column of the first cipher key(first 4 columns) and rotated it. 
Then it fed itself though the subBytes method specifically for columns. 
Finally the first column of the first block was XOR with this row and XOR with the rCon.
To flesh out the rest of the new block, the created column was then XOR with the second column of the source cipher block.
This created the next round key. 

This was repeated until it was done. 

Then the encryption/decryption process took place.
There are 4 methods that do this:
addRoundKey, subBytes, shiftRows, and mixColumns with their inverses.

addRoundKey takes the number of the round and multiples it by 4 to find the location of the staring column.
It then XORs the text by the round Key.

subBytes replaces the byte depending on the byte in the subBox array.

shiftRows basically does this

1234  ->  1234  
1234      2341
1234      3412 
1234      4123

mixColumns multiplies each column with a matrix thus mixing it up. 
I did use the Mixcolumns from the class page.

All of them have inverses which do all of the same functions but backwards.
All except addRoundKey because the inverse of a XOR is still a XOR.

