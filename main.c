/*
 *
 * QRMT Project | FC-0306-3
 * Monsoon 2025
 * RSA Password Manager
 * Hriday Koppikar
 *
 */

#include <stdlib.h> // Memory management functions, random integer generation
#include <stdio.h>  // Standard input/output functions for file management and console
#include <string.h> // String functions
#include <time.h>   // Seeding random number generation with current time
#include <limits.h> // For constants (ULLONG_MAX)

// Declaring constants and global variables
#define credentialsfile "credentials.dat"
#define FIXED_CT_LEN (sizeof(Credential) * sizeof(unsigned long long)) // Fixed ciphertext length for each credential

// RSA parameters
unsigned long long n;
unsigned long long e;
unsigned long long d;

char MASTER_PASSWORD[16];

// Structure of a credential
typedef struct
{
  char website[256];
  char username[256];
  char password[256];
} Credential;

// Defining functions

// RSA functions
unsigned long gcd(unsigned long a, unsigned long b);
unsigned long long egcd(unsigned long long a, unsigned long long b, unsigned long long *x, unsigned long long *y);
int is_prime(unsigned long long n, int interations);
unsigned long random_prime(unsigned long min, unsigned long max);
unsigned long long modular_multiply(unsigned long long a, unsigned long long b, unsigned long long mod);
unsigned long long modular_exponent(unsigned long long base, unsigned long long exp, unsigned long long mod);
unsigned long long mod_inverse(unsigned long long e, unsigned long long phi);
void encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len);
void decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len);

// Password conversion functions
void number_to_password(const unsigned long long d, char *out);
void password_to_number(const char *password, unsigned long long *out);

// File IO functions
int skip_header(FILE *file);
int load_all_credentials(FILE *file, Credential **out_array, int *out_count);
void rewrite_credentials_file(Credential *arr, int count);

// Password manager operations
void print_menu();
void save_credential(const char *site, const char *username, const char *password);
void list_credentials();
void show_credential(int index);
void edit_credential(int index);
void delete_credential(int index);

// ---------- File utility functions ---------- //
// Used some code from ChatGPT to help with these functions

// Sets file pointer to after the header
int skip_header(FILE *file)
{
  char curr[7] = {0};
  int filled = 0;

  // search 7 byte lengths
  int c;
  while ((c = fgetc(file)) != EOF) // read character by character
  {
    // add bytes to search buffer
    if (filled < 7)
    {
      curr[filled++] = (char)c;
    }
    else
    {
      // shift left
      for (int i = 0; i < 6; i++) {
        curr[i] = curr[i + 1];
      }
      curr[6] = (char)c; // add new character to end
    }

    // once 7 bytes are filled check for header end marker
    if (filled == 7 && memcmp(curr, "HDR_END", 7) == 0)
    {
      return 1; // found
    }
  }

  return 0; // not found
}

// Load all credentials from file into a credentials array and set a count variable
int load_all_credentials(FILE *file, Credential **out_array, int *out_count)
{
  if (!skip_header(file))
    return 0; // Skip header

  Credential *arr = NULL;
  int count = 0;
  unsigned char ciphertext[FIXED_CT_LEN];
  unsigned char plaintext[sizeof(Credential)];
  int plaintext_len;

  while (fread(ciphertext, 1, FIXED_CT_LEN, file) == FIXED_CT_LEN) // Read each fixed-size ciphertext block
  {
    decrypt(ciphertext, FIXED_CT_LEN, plaintext, &plaintext_len);
    if (plaintext_len != sizeof(Credential))
      break; // Plaintext is not the expected size - corrupted

    arr = realloc(arr, sizeof(Credential) * (count + 1)); // Resize array based on count
    memcpy(&arr[count], plaintext, sizeof(Credential)); // Copy decrypted credential into array (must use memcpy since Credential is a struct)

    count++;
  }

  *out_array = arr;
  *out_count = count;
  return 1;
}

// For edit and delete functions - rewrite all credentials in the file with modified array
void rewrite_credentials_file(Credential *arr, int count)
{
  FILE *file = fopen(credentialsfile, "wb");
  if (!file)
  {
    perror("Error opening file.");
    return;
  }

  // Rewrite header
  fwrite(&n, sizeof(unsigned long long), 1, file);
  fwrite(&e, sizeof(unsigned long long), 1, file);

  unsigned char sign[1024];
  unsigned char valid[] = "VALID";
  int siglen = 0;
  encrypt(valid, (int)strlen((char *)valid), sign, &siglen);

  fwrite(&siglen, sizeof(int), 1, file);
  fwrite(sign, 1, siglen, file);

  const char marker[7] = "HDR_END";
  fwrite(marker, 1, 7, file);

  // Rewrite all credentials
  for (int i = 0; i < count; i++)
  {
    unsigned char cipher[FIXED_CT_LEN];
    int cipher_len = 0;
    encrypt((unsigned char *)&arr[i], (int)sizeof(Credential), cipher, &cipher_len);

    // Expect cipher_len == FIXED_CT_LEN
    if (cipher_len != FIXED_CT_LEN)
    {
      perror("Corrupted credential data.");
      // Exit to prevent file corruption
      fclose(file);
      return;
    }

    if ((int)fwrite(cipher, 1, FIXED_CT_LEN, file) != FIXED_CT_LEN)
    {
      perror("Could not write credential data.");
      fclose(file);
      return;
    }
  }

  fflush(file); // Ensure all data is written to file
  fclose(file);
}

// ---------- Password functions ---------- //

// Convert the private exponent into a password string
void number_to_password(const unsigned long long d, char *out)
{
  char temp[64];
  sprintf(temp, "%llu", d); // convert number to text

  for (int i = 0; temp[i]; i++)
  {
    char digit = temp[i];
    out[i] = 'a' + (digit - '0'); // 0 => a, 1 => b, ..., 9 => j
  }
  out[strlen(temp)] = '\0'; // null terminate string
}

// Convert password string back into a number
void password_to_number(const char *password, unsigned long long *out)
{
  unsigned long long d = 0;
  int len = strlen(password);
  for (int i = 0; i < len; i++)
  {
    if (password[i] < 'a' || password[i] > 'j') // invalid character
    {
      *out = -1;
      return;
    }
    d *= 10; // multiple by 10 to shift left
    d += (password[i] - 'a'); // add current digit
  }
  *out = d;
  return;
}

// ---------- RSA functions ---------- //

// Euclid GCD (wrapper for extended GCD)
unsigned long gcd(unsigned long a, unsigned long b)
{
  unsigned long long tx, ty; // temp variables for extended GCD function
  return egcd(a, b, &tx, &ty);
}

// Recursive Euclid extended GCD to find modular inverse | Source: GeeksforGeeks (https://www.geeksforgeeks.org/c/c-program-for-basic-and-extended-euclidean-algorithms-2/)
unsigned long long egcd(unsigned long long a, unsigned long long b, unsigned long long *x, unsigned long long *y)
{
  if (b == 0)
  {
    *x = 1;
    *y = 0;
    return a;
  }
  unsigned long long x1, y1; // temp x and y
  unsigned long long gcd = egcd(b, a % b, &x1, &y1); // recurse function with b and a mod b until gcd found
  *x = y1;
  *y = x1 - (a / b) * y1; // identity from extended Euclid algorithm
  return gcd;
}

/* Fermat's Little Theorem to find modular inverse (inefficient for large numbers)
unsigned long long inv_fmat(unsigned long long a, unsigned long long b)
{
  return modular_exponent(a, b - 2, b); // a^(b-2) mod b
} */

// My Euclid extended GCD function that uses the method in class (more inefficient) (incomplete)
/* unsigned long long egcd(unsigned long long a, unsigned long long b, unsigned long long *x, unsigned long long *y) {
  unsigned long long arr[128][4]; // will hold equation parameters for a = qb + r
  unsigned long long ta = a, tb = b, r = 0, q = 0;
  
  int i = 0;
  while (r > 0)
  {
    q = ta/tb;
    r = ta%tb;
    
    arr[i][0] = ta;
    arr[i][1] = tb;
    arr[i][2] = q;
    arr[i][3] = r;
    
    ta = tb;
    tb = r;
    
    i++;
  }
  
  unsigned long long gcd = arr[i][3];

  return gcd;
} */

// Primality test using Fermat's Little Theorem
int is_prime(unsigned long long n, int iterations)
{
  if (n < 4)
    return 1;

  for (int i = 0; i < iterations; i++) // perform specified number of iterations
  {
    unsigned long long a = 2 + rand() % (n - 3); // random value s.t. 2 ≤ a ≤ n-2 (used AI help for this line)

    // If gcd(a, n) != 1, n is definitely composite
    if (gcd(a, n) != 1)
      return 0;

    // Fermat test (a^(n-1) mod n)
    if (modular_exponent(a, n - 1, n) != 1)
      return 0; // definitely composite
  }

  return 1; // Probably prime
}

// Find random prime in a range, using rand() and is_prime()
unsigned long random_prime(unsigned long min, unsigned long max)
{
  unsigned long x;
  do
  {
    x = (rand() % (max - min)) + min; // select random number in range (used AI help for this line)
    if (x % 2 == 0) // if x is even check the next odd number
      x++;
  } while (!is_prime(x, 20)); // Use 20 iterations for high prime probability
  return x;
}

// Binary modular multiplication and exponentiation functions generated by ChatGPT

unsigned long long modular_multiply(unsigned long long a, unsigned long long b, unsigned long long mod)
{
  unsigned long long result = 0;
  a %= mod; // intially mod a

  while (b > 0) // repeated addition (prevents overflow caused by multiplying two unsigned long long numbers)
  {
    if (b % 2 == 1)
    {
      unsigned long long temp = result + a;
      if (temp < result)
        temp %= mod; // handle overflow wrap
      result = temp % mod;
    }

    unsigned long long tempA = a + a;
    if (tempA < a)
      tempA %= mod; // handle overflow
    a = tempA % mod;

    b = b / 2;
  }
  return result;
}

unsigned long long modular_exponent(unsigned long long base, unsigned long long exp, unsigned long long mod)
{
  unsigned long long result = 1;
  base %= mod; // initially mod base

  while (exp > 0) // repeated modular multiplication
  {
    if (exp % 2 == 1)
      result = modular_multiply(result, base, mod);

    base = modular_multiply(base, base, mod);
    exp = exp / 2;
  }
  return result;
}

// My original modular multiplication and exponentiation functions (decimal based, too slow)
/* Modular multiplication function (a*b mod m)
unsigned long long modular_multiply(unsigned long long a, unsigned long long b, unsigned long long mod) {
  unsigned long long result = 0;
  // intially reduce a and b mod mod to prevent overflow and reduce computation
  a %= mod;
  b %= mod;

  if (a <= ULLONG_MAX / b) {
    // safe to multiply directly
    return (a * b) % mod;
  }

  while (b > 0) // repeated addition (prevents overflow caused by multiplying two unsigned long long numbers)
  {
    result = (result + a) % mod;
    b--;
  }

  return result;
}

// Modular exponentiation function for encryption and decryption (m^e mod n / c^d mod n)
unsigned long long modular_exponent(unsigned long long base, unsigned long long exp, unsigned long long mod) {
  if (base == 0) return 0; // 0^exp is 0 to improve efficiency

  unsigned long long result = 1;
  base %= mod; // initially mod base

  while (exp > 0) // repeated modular multiplication
  {
    result = modular_multiply(result, base, mod);
    exp--;
  }

  return result;
} */

// Modular inverse function using Euclid extended GCD
unsigned long long mod_inverse(unsigned long long e, unsigned long long phi)
{
  unsigned long long x, y;
  unsigned long long g = egcd(e, phi, &x, &y);
  if (g != 1)
    return -1; // modular inverse does not exist (e and phi are not coprime)
  x %= phi; // modular inverse of e (x mod phi)
  if (x < 0)
    x += phi; // ensure positive x
  return x;
}

// RSA encryption function
void encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int *ciphertext_len)
{
  int pos = 0;

  for (int i = 0; i < plaintext_len; ++i) // for each char in plaintext
  {
    unsigned long long m = (unsigned char)plaintext[i]; // get ASCII value of plaintext character
    unsigned long long c = modular_exponent((unsigned long long)m, e, n); // encrypt: c = p^e mod n
    memcpy(ciphertext + pos, &c, sizeof(unsigned long long)); // add encrypted character to ciphertext
    pos += sizeof(unsigned long long); // advance pointer by size of unsigned long long variable
  }
  *ciphertext_len = pos;
}

// RSA decryption function
void decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int *plaintext_len)
{
  int pos = 0;
  int pi = 0;
  while (pos < ciphertext_len)
  {
    unsigned long long c;
    memcpy(&c, ciphertext + pos, sizeof(unsigned long long)); // read encrypted character into c
    pos += sizeof(unsigned long long); // advance pointer by size of unsigned long long variable
    unsigned long long m = modular_exponent(c, d, n); // decrypt: m = c^d mod n
    plaintext[pi] = (unsigned char)m; // add decrypted character to plaintext
    pi++; // advance plaintext index
  }
  *plaintext_len = pi;
}

// ---------- Operation functions ---------- //

// Print menu function: displays available options to the user
void print_menu()
{
  printf("\nPassword Manager Menu:\n");
  printf("1. Add new credential\n");
  printf("2. List credentials\n");
  printf("3. View credential\n");
  printf("4. Edit credential\n");
  printf("5. Delete credential\n");
  printf("6. Exit\n");
  printf("Select an option: ");
}

// Save a new credential to the file
void save_credential(const char *site, const char *username, const char *password)
{
  FILE *file = fopen(credentialsfile, "ab");
  if (!file)
  {
    perror("Unable to open file.");
    return;
  }

  Credential cred;
  // insert input strings into credential struct
  snprintf(cred.website, sizeof(cred.website), "%s", site);
  snprintf(cred.username, sizeof(cred.username), "%s", username);
  snprintf(cred.password, sizeof(cred.password), "%s", password);

  unsigned char ciphertext[FIXED_CT_LEN];
  int ciphertext_len;

  encrypt((unsigned char *)&cred, sizeof(Credential), ciphertext, &ciphertext_len);

  if (ciphertext_len != FIXED_CT_LEN)
  {
    perror("Error encrypting credential.");
    fclose(file);
    return;
  }

  fwrite(ciphertext, 1, FIXED_CT_LEN, file);
  fflush(file); // Ensure all data is written to file
  fclose(file);

  // reopen and close to force write to disk
  file = fopen(credentialsfile, "rb");
  if (file) fclose(file);
}

// List all saved credentials with an index number
void list_credentials()
{
  FILE *file = fopen(credentialsfile, "rb");
  if (!file)
  {
    perror("Unable to open file.");
    return;
  }

  Credential *arr;
  int count;
  if (!load_all_credentials(file, &arr, &count)) {
    fclose(file);
    return;
  }
  fclose(file);

  for (int i = 0; i < count; i++)
  {
    printf("%d: %s@%s\n", i + 1, arr[i].username, arr[i].website); // list all saved credentials in the format index: username@website
  }
  if (count == 0)
  {
    printf("No credentials saved yet.\n");
  }
  free(arr);
  printf("\nTotal count: %d\n", count);
}

// Reveal a specific credential
void show_credential(int index)
{
  FILE *file = fopen(credentialsfile, "rb");
  if (!file)
  {
    perror("Unable to open file. No credentials saved yet.");
    return;
  }

  index--; // convert to 0-based index

  Credential *arr;
  int count;

  if (!load_all_credentials(file, &arr, &count)) {
    fclose(file);
    return;
  }
  fclose(file);

  if (index < 0 || index >= count)
  {
    printf("\nInvalid index.\n");
    free(arr);
    return;
  }

  // display credential
  printf("\nViewing credential %d:\n", index + 1);
  printf("Website: %s\n", arr[index].website);
  printf("Username: %s\n", arr[index].username);
  printf("Password: %s\n", arr[index].password);

  free(arr); // free allocated memory
  return;
}

// Edit a specific credential
void edit_credential(int index)
{
  FILE *file = fopen(credentialsfile, "rb");
  if (!file)
  {
    printf("Unable to open file.\n");
    return;
  }

  Credential *arr;
  int count;

  if (!load_all_credentials(file, &arr, &count))
  {
    fclose(file);
    return;
  }
  fclose(file);

  index--; // convert to 0-based index

  if (index < 0 || index >= count)
  {
    printf("\nInvalid index.\n");
    free(arr);
    return;
  }

  // Input updated details into array
  printf("Editing credential for %s\n", arr[index].website);
  printf("New username: ");
  scanf("%255s", arr[index].username);
  getchar();
  printf("New password: ");
  scanf("%255s", arr[index].password);
  getchar();

  // Rewrite file with edited array
  rewrite_credentials_file(arr, count);

  printf("\nCredential updated.\n");
  free(arr); // Free allocated memory
}

// Delete a specific credential
void delete_credential(int index)
{
  FILE *file = fopen(credentialsfile, "rb");
  if (!file)
  {
    printf("Could not open file.\n");
    return;
  }

  Credential *arr;
  int count;

  if (!load_all_credentials(file, &arr, &count))
  {
    fclose(file);
    return;
  }
  fclose(file);

  index--; // convert to 0-based index

  if (index < 0 || index >= count)
  {
    printf("\nInvalid index.\n");
    free(arr);
    return;
  }

  count--; // reduce count to account for deletion and to trim duplicate last entry on rewrite

  // Shift credentials after index left
  for (int i = index; i < count; i++)
  {
    arr[i] = arr[i + 1];
  }

  rewrite_credentials_file(arr, count);

  printf("\nCredential deleted.\n");
  free(arr); // Free allocated memory
}

// Main function
int main()
{
  int choice;
  int index;
  char site[256], username[256], password[256];

  // Seeded random number generator with current UNIX epoch time
  srand((unsigned)time(NULL));

  printf("Welcome to the Password Manager!\n");

  FILE *fc = fopen(credentialsfile, "rb"); // Check if credentials file exists

  if (fc != NULL) // File exists
  {
    FILE *file = fopen(credentialsfile, "rb");
    printf("Enter your master password: ");
    scanf("%15s", MASTER_PASSWORD);
    getchar();

    unsigned char sign[1024];
    unsigned char valid[1024];

    password_to_number(MASTER_PASSWORD, &d); // Store password as private exponent

    // Read public key
    fread(&n, sizeof(unsigned long long), 1, file);
    fread(&e, sizeof(unsigned long long), 1, file);

    // Read signature length and signature
    int siglen = 0;
    fread(&siglen, sizeof(int), 1, file);
    if (siglen <= 0 || siglen > (int)sizeof(sign))
    {
      perror("Invalid file signature.");
      return 1;
    }
    fread(sign, 1, siglen, file);
    int valid_len = 0;

    decrypt(sign, siglen, valid, &valid_len); // Attempt to decrypt signature with user provided password

    // Check if decryption matches expected "VALID" string
    if (valid_len != 5 || memcmp(valid, "VALID", 5) != 0)
    {
      perror("Incorrect master password.\n");
      return 0;
    }

    printf("\nUnlocked!\n");

    fclose(file);
    fclose(fc);
  }
  else // File does not exist - first time initialisation
  {
    FILE *file = fopen(credentialsfile, "wb");

    printf("First time initialisation...\n");

    // Generate RSA keypair
    unsigned long p = random_prime(50000, 100000);
    unsigned long q = random_prime(50000, 100000);

    n = p * q;

    e = random_prime(1000, 3000); // Small public exponent

    unsigned long long m = (p - 1) * (q - 1);

    d = mod_inverse(e, m); // Private exponent

    // Sign file header with private exponent
    unsigned char sign[1024];
    unsigned char valid[] = "VALID";
    int siglen = 0;
    memset(sign, 0, sizeof(sign));
    encrypt(valid, strlen((char *)valid), sign, &siglen);
    fwrite(&n, sizeof(unsigned long long), 1, file);
    fwrite(&e, sizeof(unsigned long long), 1, file);
    fwrite(&siglen, sizeof(int), 1, file); // store sign length
    fwrite(sign, 1, siglen, file);

    // Write end of header marker
    const char marker[7] = "HDR_END";
    fwrite(marker, 1, 7, file);

    // Generate and display master password
    number_to_password(d, MASTER_PASSWORD);
    printf("Your random master password (ONLY VIEWABLE ONCE): ");
    printf("%s\n", MASTER_PASSWORD);

    // Prompt user to save password
    printf("\nPress ENTER to continue...");
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);

    printf("\nPassword Manager initialised!\n");

    fflush(file); // Ensure all data is written to file
    fclose(file);
  }

  // Main loop
  while (1)
  {
    // Display menu and get user choice
    print_menu();
    scanf("%d", &choice);
    getchar();

    // Handle user choice
    switch (choice)
    {
    case 1: // Add credential
      printf("\nEnter site name: ");
      scanf("%255s", site);
      getchar();
      printf("Enter username: ");
      scanf("%255s", username);
      getchar();
      printf("Enter password: ");
      scanf("%255s", password);
      getchar();
      save_credential(site, username, password);
      printf("\nPassword saved successfully!\n");
      break;

    case 2: // List credentials
      printf("\nSaved Credentials\n\n");
      list_credentials();
      break;

    case 3: // Show credential
      printf("\nSaved Credentials\n\n");
      list_credentials();
      printf("Enter number to view: ");
      scanf("%d", &index);
      getchar();
      show_credential(index);
      break;

    case 4: // Edit credential
      printf("\nSaved Credentials\n\n");
      list_credentials();
      printf("Enter number to edit: ");
      scanf("%d", &index);
      getchar();
      edit_credential(index);
      break;

    case 5: // Delete credential
      printf("\nSaved Credentials\n\n");
      list_credentials();
      printf("Enter number to delete: ");
      scanf("%d", &index);
      getchar();
      delete_credential(index);
      break;

    case 6: // Exit
      printf("Exiting...\n");
      return 0;

    default: // Invalid choice
      printf("\nInvalid choice! Please try again.\n");
    }
  }
  return 0;
}