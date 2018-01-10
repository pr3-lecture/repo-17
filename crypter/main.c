#include <memory.h>
#include <stdio.h>
#include "crypto.h"
#include "regex.h"

//#define DEBUG

/**
 * Ermittelt anhand des Namens mit dem das Programm
 * aufgerufen wurde den auszuführenden Modus.
 * @param programname Name mit welchem das Programm aufgerufen wurde
 * @return 0 (Encrypt) bzw. 1 (Decrypt)
 */
int getMode(char* programname) {
	regex_t regex;
	int modeFound;
	int chosenMode = -1;

	/* Prüfe ob das Programm mit dem Namen "enrcypt" aufgerufen wurde.
	 * Wenn ja setze den gewählten Modus auf 0. */
	regcomp(&regex, "encrypt", 0);
	modeFound = regexec(&regex, programname, 0, NULL, 0);

	if (modeFound == 0) {
		chosenMode = 0;
	}

	/* Prüfe ob das Programm mit dem Namen "dercypt" aufgerufen wurde.
	 * Wenn ja setze den gewählten Modus auf 1. */
	regcomp(&regex, "decrypt", 0);
	modeFound = regexec(&regex, programname, 0, NULL, 0);

	if (modeFound == 0) {
		chosenMode = 1;
	}

	regfree(&regex);
	return chosenMode;
}

int main(int args, char** argv) {
	/* Modus bestimmen: Encrypt (0) oder Decrypt (1) */
	int mode = getMode(argv[0]);

	/* Wenn Modus weder Encrypt noch Decrypt ist bricht das Programm ab. */
	if (mode == -1) {
		printf(
				"Ungueltiger Programmname! Gueltige Namen: \"encrypt\" und \"decrypt\".");
		return -1;
	}

	KEY k;
	k.chars = argv[1];

	/* Wenn kein Key eingegeben wurde, bricht das Programm ab. */
	if (argv[1] == NULL) {
		printf("Bitte einen Schluessel eingeben!");
		return -1;
	}

	/* Wenn 2. Parameter vorhanden: Lies Eingaben aus der Datei. */
	char eingabe[100];
	if (argv[2] != NULL) {
		FILE* f = fopen(argv[2], "r");

		if (f != NULL) {
			fgets(eingabe, 100, f);
			fclose(f);
		}
		/* Wenn kein 2. Parameter vorhanden: Lies Eingaben aus der Konsole. */
	} else {
		printf("Bitte Nachricht eingeben: ");
		scanf("%s", eingabe);
	}

	char ergebnis[strlen(eingabe)];

	if (mode == 0) {
		if (encrypt(k, eingabe, ergebnis) == 0) {
			printf("Nachricht: %s\nSchluessel: %s\nErgebnis: %s\n", eingabe,
					argv[1], ergebnis);
		}
	} else if (mode == 1) {
		if (decrypt(k, eingabe, ergebnis) == 0) {
			printf("Nachricht: %s\nschluessel: %s\nErgebnis: %s\n", eingabe,
					argv[1], ergebnis);
		}
	}

	return 0;
}
