/*
 * Copyright (c) 2026 Michaël Moser.
 *
 * Auteur : Michaël Moser
 * Tous droits réservés.
 */


/** Implémentation TOTP (RFC 6238) utilisant HMAC-SHA1 et des codes à 6 chiffres. */

package com.astier.bts.totp;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class Totp {
    // Secret Base32 partagé avec l'application d'authentification.
    private static final String CLEF_TOTP = "53UPAEE2VF5CXGZ6MHDE7W64VRP7CBDB";
    private static final int PERIODE_SECONDES = 30;
    private static final int NOMBRE_CHIFFRES = 6;

    private int codePourCompteur() throws Exception {
        long compteur = System.currentTimeMillis() / 1000L / PERIODE_SECONDES;
        byte[] compteurBytes = longEnOctets(compteur);
        byte[] secretBytes = decoderBase32(CLEF_TOTP);
        //HmacSHA1 produit une empreinte de 160 bits, soit 20 octets.
        Mac hmac = Mac.getInstance("HmacSHA1");
        hmac.init(new SecretKeySpec(secretBytes, "HmacSHA1"));
        byte[] empreinte = hmac.doFinal(compteurBytes);
        return extraireCode(empreinte);
    }

    // Truncate de HOTP (empreinte HMAC --> code numérique RFC 6238)
    private int extraireCode(byte[] empreinte) {
        // La RFC prend les 4 bits de poids faible du dernier octet HMAC.
        // Ils donnent un décalage entre 0 et 15 dans l’empreinte.Troncature dynamique
        int troncatureDynamique = empreinte[empreinte.length - 1] & 0x0f;
        int valeur = ((empreinte[troncatureDynamique] & 0x7f) << 24)    //0x7f ignore le bit de signe du premier octet pour obtenir une valeur positive.
                | ((empreinte[troncatureDynamique + 1] & 0xff) << 16)   //0xff traite les autres octets comme des valeurs non signées
                | ((empreinte[troncatureDynamique + 2] & 0xff) << 8)    //0xff traite les autres octets comme des valeurs non signées
                | (empreinte[troncatureDynamique + 3] & 0xff);          //0xff traite les autres octets comme des valeurs non signées
        return valeur % ((int) Math.pow(10, NOMBRE_CHIFFRES));
    }

    public boolean testCodeTOTP(int code) throws Exception {
        return codePourCompteur() == code;
    }

    private byte[] longEnOctets(long valeur) {
        byte[] octets = new byte[8];
        for (int i = 7; i >= 0; i--) {
            octets[i] = (byte) valeur;
            valeur >>>= 8;
        }
        return octets;
    }

    /** Convertit le secret Base32 en octets avec Apache Commons Codec. */
    private byte[] decoderBase32(String secret) {
        return Base32.builder().get().decode(secret);
    }
}
