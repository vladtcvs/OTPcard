package com.vladtcvs.otpcard;

import javacard.framework.*;
import javacard.security.*;

// Here we implement HOTP RFC-4226
// https://datatracker.ietf.org/doc/html/rfc4226

/*
 * Commands:
 *      HOTP                - generate new HOTP
 *          Arguments:  PIN, secret id, challenge
 *          Returns:    status, OTP
 *
 *      SAVE_PIN            - save new PIN
 *          Arguments:  old PIN, new PIN
 *          Returns:    status
 *
 *      UNBLOCK_PIN         - reset PIN counter
 *          Arguments:  AdminPIN, new PIN
 *          Returns:    status
 *
 *      SAVE_ADMIN_PIN      - save new AdminPIN
 *          Arguments:  oldAdminPIN, newAdminPIN
 *          Returns:    status
 * 
 *      SAVE_NEW_SECRET     - saves new secret to card
 *          Arguments:  PIN, secret value, secret name, current time, secret metadata, hash method (SHA1, SHA256, SHA512)
 *          Returns:    status, secret id
 *
 *      DELETE_SECRET       - delete secret
 *          Arguments:  PIN, secret id
 *          Returns:    status
 *
 *      GET_SECRET_STATUS   - get name and usage status (used or not) of secret with id
 *          Arguments:  PIN, id
 *          Returns:    status, secret name, secret used flag, hash method (SHA1, SHA256, SHA512)
 *
 *      GET_INFO            - get info about applet
 *          Arguments:
 *          Returns:    status, applet info, max amount of secrets, max secret name length, max secret length
 * 
 *      secret values never leaves the card! If you need backup, do it during adding procedure
 */

public class OTPCard extends Applet {

    private interface INS {
        byte HMAC = (byte) 0x01;
        byte GET_SECRET_STATUS = (byte) 0x02;
        byte SAVE_NEW_SECRET = (byte) 0x03;
        byte DELETE_SECRET = (byte) 0x04;

        byte SAVE_PIN = (byte) 0x05;
        byte UNBLOCK_PIN = (byte) 0x06;
        byte SAVE_ADMIN_PIN = (byte) 0x07;

        byte GET_INFO = (byte) 0x08;
    }

    private interface HMAC_HASH {
        byte NONE = (byte)0x00;
        byte SHA1 = (byte)0x01;
        byte SHA256 = (byte)0x02;
        byte SHA512 = (byte)0x03;
    }

    private class OTPRecord {
        private byte method;
        private byte[] name;
        private byte name_length;
        private byte[] secret;
        private MessageDigest digest;
        private byte[] ipad;
        private byte[] opad;

        public OTPRecord(byte maxNameLength)
        {
            name = new byte[maxNameLength];
            name_length = 0;
            secret = new byte[64];
            digest = null;
            method = HMAC_HASH.NONE;

            ipad = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
            opad = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
            for (short i = 0; i < name.length; ++i)
                name[0] = 0;
        }

        private short GenerateHMAC_SHA1(byte[] challenge, byte[] buffer)
        {
            if (buffer.length < 20)
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            for (short i = 0; i < 64; i++) {
                ipad[i] = (byte) (secret[i] ^ 0x36);
                opad[i] = (byte) (secret[i] ^ 0x5C);
            }

            byte[] inner = JCSystem.makeTransientByteArray((short)20, JCSystem.CLEAR_ON_DESELECT);
            digest.reset();
            digest.update(ipad, (short) 0, (short) 64);
            digest.update(challenge, (short) 0, (short) challenge.length);
            digest.doFinal(inner, (short) 0, (short) 0, inner, (short) 0);
            digest.reset();
            digest.update(opad, (short) 0, (short) 64);
            digest.doFinal(inner, (short) 0, (short) 20, buffer, (short) 0);
            return 20;
        }

        private short GenerateHMAC_SHA256(byte[] challenge, byte[] buffer)
        {
            return 32;
        }

        private short GenerateHMAC_SHA512(byte[] challenge, byte[] buffer)
        {
            return 64;
        }

        public short GenerateHMAC(byte[] challenge, byte[] buffer)
        {
            if (method == HMAC_HASH.NONE) {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
                return 0;
            }

            switch (method) {
            case HMAC_HASH.SHA1:
                return GenerateHMAC_SHA1(challenge, buffer);
            case HMAC_HASH.SHA256:
                return GenerateHMAC_SHA256(challenge, buffer);
            case HMAC_HASH.SHA512:
                return GenerateHMAC_SHA512(challenge, buffer);
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                return 0;
            }
        }

        public void FillRecord(byte[] buffer,
                               short secret_off, byte secret_len,
                               short name_off, byte name_len,
                               byte new_method) throws ISOException
        {
            if (name_len > name.length || secret_len > secret.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            try {
                switch (new_method) {
                case HMAC_HASH.SHA1:
                    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
                    break;
                case HMAC_HASH.SHA256:
                    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
                    break;
                case HMAC_HASH.SHA512:
                    digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            } catch (CryptoException e) {
                if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
            method = new_method;
            Util.arrayCopyNonAtomic(buffer, secret_off, secret, (short)0, secret_len);
            Util.arrayCopyNonAtomic(buffer, name_off, name, (short)0, name_len);
            name_length = name_len;
            // We always store 64 bytes, because we do XOR during HMAC
            // So if we have secret less 64 bytes, it can be discovered
            // By power usage or delays
            for (short i = secret_len; i < 64; i++)
                secret[i] = 0;
        }

        public void Clear()
        {
            name_length = 0;
            method = HMAC_HASH.NONE;
            digest = null;
        }

        public boolean IsUsed()
        {
            return method != HMAC_HASH.NONE;
        }

        public byte GetMethod()
        {
            return method;
        }

        public byte[] GetName()
        {
            byte[] ret = JCSystem.makeTransientByteArray(name_length, JCSystem.CLEAR_ON_DESELECT);
            Util.arrayCopyNonAtomic(name, (short)0, ret, (short)0, name_length);
            return ret;
        }
    }

    // Secrets
    private OTPRecord[] otp_records;

    // Default data
    private static final byte[] PIN_DEFAULT = {'1', '2', '3', '4', '5', '6'};
    private static final byte[] ADMIN_PIN_DEFAULT = {'1', '2', '3', '4', '5', '6', '7', '8'};
    private static final byte MAX_PIN_SIZE = 31;
    private static final byte MIN_PIN_SIZE = 6;

    // Data configured from parameters
    private final byte maxSecrets;
    private final byte maxSecretNameLength;
    private final byte[] serial_number;

    // Card capabilities
    private final byte sha1support;
    private final byte sha256support;
    private final byte sha512support;

    // Persistent data
    private OwnerPIN PIN;
    private OwnerPIN AdminPIN;

    protected OTPCard(byte[] buf, short offData, byte lenData) {
        if (lenData != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short off = offData;
        maxSecrets = buf[off++];
        maxSecretNameLength = buf[off++];

        byte PIN_reset_count = buf[off++];
        byte AdminPIN_reset_count = buf[off++];

        serial_number = new byte[4];
        for (short i = 0; i < 4; i++)
            serial_number[i] = buf[off++];

        sha1support = 1;
        sha256support = 0;
        sha512support = 0;

        PIN = new OwnerPIN(PIN_reset_count, MAX_PIN_SIZE);
        PIN.update(PIN_DEFAULT, (short)0, (byte)PIN_DEFAULT.length);

        AdminPIN = new OwnerPIN(AdminPIN_reset_count, MAX_PIN_SIZE);
        AdminPIN.update(ADMIN_PIN_DEFAULT, (short)0, (byte)ADMIN_PIN_DEFAULT.length);

        otp_records = new OTPRecord[maxSecrets];
        for (short i = 0; i < maxSecrets; i++)
            otp_records[i] = new OTPRecord(maxSecretNameLength);
    }

    public static void install(byte[] buf, short off, byte bLength) {
        short pos = off;
        // find AID
        byte  lenAID = buf[pos++];
        short offAID = pos;
        pos += lenAID;
        // find control information (ignored)
        byte  lenCI = buf[pos++];
        //short offCI = pos;
        pos += lenCI;
        // find applet data
        byte  lenAD = buf[pos++];
        short offAD = pos;
        pos += lenAD;
        OTPCard applet = new OTPCard(buf, offAD, lenAD);
        applet.register(buf, offAID, lenAID);
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        // Handle SELECT APDU (mandatory)
        if (selectingApplet()) {
            return;
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS.HMAC:
                generateHMAC(apdu);
                break;
            case INS.GET_SECRET_STATUS:
                getSecretStatus(apdu);
                break;
            case INS.SAVE_NEW_SECRET:
                storeSecret(apdu);
                break;
            case INS.DELETE_SECRET:
                clearSecret(apdu);
                break;

            case INS.SAVE_PIN:
                updatePin(apdu, PIN);
                break;
            case INS.UNBLOCK_PIN:
                unblockPin(apdu);
                break;
            case INS.SAVE_ADMIN_PIN:
                updatePin(apdu, AdminPIN);
                break;

            case INS.GET_INFO:
                getInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * 
     * @param buffer buffer with data
     * @param offset offset of target area of buffer
     * @param len length of target area of buffer
     * @param position position in target area of buffer
     * @return position of data begin, length of data
     * @throws ISOException
     */
    private void getRecord(byte[] buffer, short offset, short len, short position, short[] out) throws ISOException
    {
        if ((short)(offset + len) > buffer.length)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        if (position >= len)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short rec_len = buffer[(short)(offset + position)];
        if ((short)(position + 1 + rec_len) > len)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        out[0] = (short)(position + 1);
        out[1] = rec_len;
        out[2] = (short)(position + 1 + rec_len);
    }

    private void getReceivedData(byte[] buffer, short[] out) throws ISOException
    {
        getRecord(buffer, (short)0, (short)buffer.length, (short)ISO7816.OFFSET_LC, out);
    }

    /*private short getEClength(byte[] buffer, short lc_len)
    {
        short ec_offset = (short)(ISO7816.OFFSET_LC + 1 + lc_len);
        if (ec_offset >= buffer.length)
            return 0;
        return buffer[ec_offset];
    }*/

    private void getPin(byte[] buffer, short lc_offset, short lc_len, short pos, short[] out) throws ISOException
    {
        getRecord(buffer, lc_offset, lc_len, pos, out);
    }

    private void getNumber(byte[] buffer, short lc_offset, short lc_len, short pos, short[] out) throws ISOException
    {
        if (pos >= lc_len)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        out[0] = pos;
        out[1] = (short)1;
        out[2] = (short)(pos + 1);
    }

    private void generateHMAC(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);

        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];
        //short ec_len = getEClength(buffer, lc_len);

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <PIN_LEN> PIN <SECRET ID> <CHALLENGE LEN> CHALLENGE
        // Returned array with hash result
        short pos = 0;
        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short cur_pin_pos = readed[0];
        short cur_pin_len = readed[1];
        pos = readed[2];

        getNumber(buffer, off_lc_data, lc_len, pos, readed);
        short secret_id_pos = readed[0];
        byte id = buffer[(short)(off_lc_data + secret_id_pos)];
        pos = readed[2];

        getRecord(buffer, off_lc_data, lc_len, pos, readed);
        short challenge_pos = readed[0];
        short challenge_len = readed[1];
        byte[] challenge_data = JCSystem.makeTransientByteArray(challenge_len, JCSystem.CLEAR_ON_DESELECT);;
        Util.arrayCopyNonAtomic(buffer, (short)(off_lc_data + challenge_pos), challenge_data, (short)0, challenge_len);
        pos = readed[2];

        if (!PIN.check(buffer, (short)(off_lc_data + cur_pin_pos), (byte)cur_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (id >= otp_records.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short hmac_len = otp_records[id].GenerateHMAC(challenge_data, buffer);
        apdu.setOutgoingAndSend((short) 0, hmac_len);
    }

    private void getSecretStatus(APDU apdu)
    {
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        byte[] buffer = apdu.getBuffer();
        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];
        //short ec_len = getEClength(buffer, lc_len);

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <PIN_LEN> PIN <SECRET ID>
        // Returned data has form <USED> <NAME LEN> NAME <METHOD>
        short pos = 0;
        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short cur_pin_pos = readed[0];
        short cur_pin_len = readed[1];
        pos = readed[2];

        getNumber(buffer, off_lc_data, lc_len, pos, readed);
        short secret_id_pos = readed[0];
        byte id = buffer[(short)(off_lc_data + secret_id_pos)];

        if (!PIN.check(buffer, (short)(off_lc_data + cur_pin_pos), (byte)cur_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (id >= otp_records.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        byte used = otp_records[id].IsUsed() ? (byte)1 : (byte)0;
        byte[] name = otp_records[id].GetName();
        byte method = otp_records[id].GetMethod();

        if (buffer.length < (short)(3 + name.length))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short anslen = 0;
        buffer[anslen++] = used;
        buffer[anslen++] = (byte)name.length;
        for (short i = 0; i < name.length; i++)
            buffer[anslen++] = name[i];
        buffer[anslen++] = method;
        apdu.setOutgoingAndSend((short) 0, anslen);
    }

    private void updatePin(APDU apdu, OwnerPIN pin)
    {
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        byte[] buffer = apdu.getBuffer();
        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <PIN_LEN> PIN <NEW_PIN_LEN> NEWPIN
        short pos = 0;
        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short cur_pin_pos = readed[0];
        short cur_pin_len = readed[1];
        pos = readed[2];

        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short new_pin_pos = readed[0];
        short new_pin_len = readed[1];
        pos = readed[2];

        if ((short)(cur_pin_len + new_pin_len + 2) != lc_len)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        if (new_pin_len > MAX_PIN_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        if (new_pin_len < MIN_PIN_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // So we have old pin and new pin now
        // Check pin
        short attempts = pin.getTriesRemaining();
        if (attempts == 0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        if (!pin.check(buffer, (short)(off_lc_data + cur_pin_pos), (byte)cur_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        JCSystem.beginTransaction();
        pin.update(buffer, (short)(off_lc_data + new_pin_pos), (byte)new_pin_len);
        pin.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    private void unblockPin(APDU apdu)
    {
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        byte[] buffer = apdu.getBuffer();
        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <ADMIN_PIN_LEN> ADMIN_PIN
        getPin(buffer, off_lc_data, lc_len, (short)0, readed);
        short admin_pin_pos = readed[0];
        short admin_pin_len = readed[1];

        // Check pin
        short attempts = AdminPIN.getTriesRemaining();
        if (attempts == 0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        if (!AdminPIN.check(buffer, (short)(off_lc_data + admin_pin_pos), (byte)admin_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        JCSystem.beginTransaction();
        PIN.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    private void getInfo(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();

        if (buffer.length < 10)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short anslen = 0;
        buffer[anslen++] = maxSecrets;
        buffer[anslen++] = maxSecretNameLength;
        buffer[anslen++] = 64; // max Secret length
        buffer[anslen++] = sha1support;
        buffer[anslen++] = sha256support;
        buffer[anslen++] = sha512support;
        buffer[anslen++] = serial_number[0];
        buffer[anslen++] = serial_number[1];
        buffer[anslen++] = serial_number[2];
        buffer[anslen++] = serial_number[3];
        apdu.setOutgoingAndSend((short) 0, anslen);
    }

    private void storeSecret(APDU apdu)
    {
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        byte[] buffer = apdu.getBuffer();
        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];

        // Data has form <PIN LEN> PIN <SECRET ID> <SECRET LEN> SECRET <NAME LEN> NAME <METHOD>
        short pos = 0;

        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short cur_pin_pos = readed[0];
        short cur_pin_len = readed[1];
        pos = readed[2];

        getNumber(buffer, off_lc_data, lc_len, pos, readed);
        short secret_id_pos = readed[0];
        byte id = buffer[(short)(off_lc_data + secret_id_pos)];
        pos = readed[2];

        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short secret_pos = readed[0];
        short secret_len = readed[1];
        pos = readed[2];

        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short name_pos = readed[0];
        short name_len = readed[1];
        pos = readed[2];

        getNumber(buffer, off_lc_data, lc_len, pos, readed);
        short method_pos = readed[0];
        byte method = buffer[(short)(off_lc_data + method_pos)];
        pos = readed[2];

        if (!PIN.check(buffer, (short)(off_lc_data + cur_pin_pos), (byte)cur_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (id >= otp_records.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        switch (method) {
            case HMAC_HASH.SHA1:
                if (sha1support == 0)
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
            case HMAC_HASH.SHA256:
                if (sha256support == 0)
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
            case HMAC_HASH.SHA512:
                if (sha512support == 0)
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
        }

        otp_records[id].FillRecord(buffer,
                                   (short)(off_lc_data + secret_pos), (byte)secret_len,
                                   (short)(off_lc_data + name_pos), (byte)name_len,
                                   method);
    }

    private void clearSecret(APDU apdu)
    {
        short[] readed = JCSystem.makeTransientShortArray((short)3, JCSystem.CLEAR_ON_DESELECT);
        byte[] buffer = apdu.getBuffer();
        getReceivedData(buffer, readed);
        short off_lc_data = readed[0];
        short lc_len = readed[1];

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <PIN_LEN> PIN <NEW_PIN_LEN> NEWPIN
        short pos = 0;
        getPin(buffer, off_lc_data, lc_len, pos, readed);
        short cur_pin_pos = readed[0];
        short cur_pin_len = readed[1];
        pos = readed[2];

        getNumber(buffer, off_lc_data, lc_len, pos, readed);
        short secret_id_pos = readed[0];
        byte id = buffer[(short)(off_lc_data + secret_id_pos)];
        if (!PIN.check(buffer, (short)(off_lc_data + cur_pin_pos), (byte)cur_pin_len))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (id >= otp_records.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        otp_records[id].Clear();
    }
}
