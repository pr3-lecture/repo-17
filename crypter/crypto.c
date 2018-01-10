#include <stdio.h>
#include <memory.h>
#include "crypto.h"

/**
 * Prueft, ob eine Zeichenkette ungueltige Zeichen enthaelt
 * @param mode encrypt (0) oder decrypt (1)
 * @param message Zu pruefende Zeichenkette
 * @return 0 wenn ungueltige Zeichen vorkommen, ansonsten 1
 */
int checkValidCharacters(int mode, const char* message) {
	char* alphabet;

	if (mode == 0) {
		alphabet = MESSAGE_CHARACTERS;
	} else {
		alphabet = CYPHER_CHARACTERS;
	}

	for (int i = 0; i < strlen(message); i++) {
		char zeichen = message[i];
		int validCharacter = 0;

		for (int j = 0; j < strlen(alphabet); j++) {
			if (zeichen == alphabet[j]) {
				validCharacter = 1;
				break;
			}
		}

		if (validCharacter == 0) {
			return 0;
		}
	}

	return 1;
}

/**
 * Prueft, ob Schluessel und (verschlüsselte) Nachricht gueltig sind.
 * @param k Key
 * @param message (Verschluesselte) Nachricht
 * @param mode encrypt (0) oder decrypt (1)
 * @return 0 wenn alles gültig ist, ansonsten entsprechenden Fehlercode
 */
int checkKeyAndMessage(KEY k, char* message, int mode) {
	/* Laenge des Schluessels pruefen */
	if (strlen(k.chars) < 2) {
		printf("Schluessel zu kurz");
		return E_KEY_TOO_SHORT;
	}

	/* Encrypt */
	if (mode == 0) {
		/* Inhalt der Nachricht pruefen */
		if (checkValidCharacters(0, message) == 0) {
			printf("Ungueltige Zeichen in der Nachricht");
			return E_MESSAGE_ILLEGAL_CHAR;
		}

		if (checkValidCharacters(0, k.chars) == 0) {
			printf("Ungueltige Zeichen im Schluessel");
			return E_KEY_ILLEGAL_CHAR;
		}
		/* Decrypt */
	} else {
		/* Inhalt der Nachricht pruefen */
		if (checkValidCharacters(1, message) == 0) {
			printf("Ungueltige Zeichen in der Nachricht");
			return E_CYPHER_ILLEGAL_CHAR;
		}

		/* Inhalt des Schluessels pruefen */
		if (checkValidCharacters(1, k.chars) == 0) {
			printf("Ungueltige Zeichen im Schluessel");
			return E_KEY_ILLEGAL_CHAR;
		}
	}

	return 0;
}

/**
 * Gibt die Stelle eines Zeichens in einem uebergebenen Alphabet zurueck
 * @param x Zeichen
 * @param alphabet Alphabet
 * @return Stelle des Buchstabens im Alphabet
 */
int positionInAlphabet(char character, const char* alphabet) {
	for (int i = 0; i < strlen(alphabet); i++) {
		if (alphabet[i] == character) {
			return i;
		}
	}
	return -1;
}

/**
 * Wendet die XOR-Funktion auf eine Zeichenkette an
 * @param key Schluessel zum Ver- und Entschluesseln
 * @param message Nachricht
 * @param cryptedMessage Ergebnis
 * @param mode encrypt (0) oder decrypt (1)
 * @param length Laenge der Nachricht
 */
void crypt(KEY key, const char* message, char* cryptedMessage, int mode,
		int length) {
	for (int i = 0; i < length; i++) {
		/* Position im Schluessel anpassen, da Schluessel kuerzer sein kann als Nachricht */
		int positionInKey = (int) (i % strlen(key.chars));
		int positionKeyInAlphabet = positionInAlphabet(key.chars[positionInKey],
				KEY_CHARACTERS) + 1;

		int positionMessage = 0;
		/* Encrypt */
		if (mode == 0) {
			positionMessage = positionInAlphabet(message[i], MESSAGE_CHARACTERS)
					+ 1;
			cryptedMessage[i] =
					CYPHER_CHARACTERS[positionMessage ^ positionKeyInAlphabet];
		/* Decrypt */
		} else if (mode == 1) {
			positionMessage = positionInAlphabet(message[i], CYPHER_CHARACTERS);
			cryptedMessage[i] = MESSAGE_CHARACTERS[(positionMessage
					^ positionKeyInAlphabet) - 1];
		}
	}

	/* '\0' anhaengen */
	cryptedMessage[strlen(message)] = '\0';
}

/**
 * Verschluesselt eine Nachricht
 * @param key Key zum Verschluesseln
 * @param input Nachricht in Klartext
 * @param output Verschluesselte Nachricht
 * @return 0 wenn alles ok, ansonsten Fehlercode
 */
int encrypt(KEY key, const char* input, char* output) {
	if (checkKeyAndMessage(key, (char *) input, 0) == 0) {
		crypt(key, input, output, 0, (int) strlen(input));
		return 0;
	} else {
		return 5;
	}
}

/**
 * Entschluesselt eine nachricht
 * @param key Key zum Entschluesseln
 * @param cypherText Verschluesselte Nachricht
 * @param output Nachricht in Klartext
 * @return 0 wenn alles ok, ansonsten Fehlercode
 */
int decrypt(KEY key, const char* cypherText, char* output) {
	if (checkKeyAndMessage(key, (char *) cypherText, 1) == 0) {
		crypt(key, cypherText, output, 1, (int) strlen(cypherText));
		return 0;
	} else {
		return 5;
	}
}
