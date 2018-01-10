#include <stdio.h>
#include <memory.h>
#include "crypto.h"

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                                if (message) return message; } while (0)
//#define DEBUG

int tests_run = 0;
static char* testVerschluesseln() {
	char* text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	KEY k;
	k.chars = "TPERULES";
	char* erwartetesErgebnis = "URFVPJB[]ZN^XBJCEBVF@ZRKMJ";
	char ergebnis[strlen(text)];

	encrypt(k, text, ergebnis);
#ifdef DEBUG
	printf("Erwartetes Ergebnis: %s, IST-Ergebnis: %s\n", erwartetesErgebnis, ergebnis);
#endif
	mu_assert("Verschluesselung erfolgreich",
			strcmp(erwartetesErgebnis, ergebnis) == 0);
	return 0;
}

static char* testEntschluesseln() {
	char* text = "URFVPJB[]ZN^XBJCEBVF@ZRKMJ";
	KEY k;
	k.chars = "TPERULES";
	char* erwartetesErgebnis = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char ergebnis[strlen(text)];

	decrypt(k, text, ergebnis);
#ifdef DEBUG
	printf("Erwartetes Ergebnis: %s, IST-Ergebnis: %s\n", erwartetesErgebnis, ergebnis);
#endif
	mu_assert("Entschluesselung erfolgreich",
			strcmp(erwartetesErgebnis, ergebnis) == 0);
	return 0;
}

static char* allTests() {
	mu_run_test(testVerschluesseln);
	mu_run_test(testEntschluesseln);
	return 0;
}

int main() {
	char* result = allTests();

	if (result != 0) {
		printf("%s\n", result);
	} else {
		printf("ALL TESTS PASSED\n");
	}

	printf("Tests run: %d\n", tests_run);

	return result != 0;
}