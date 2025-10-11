package otpcard;

import javacard.framework.*;

// Here we implement HOTP RFC-4226 and TOTP RFC-6238
// https://datatracker.ietf.org/doc/html/rfc4226
// https://datatracker.ietf.org/doc/html/rfc6238

/*
 * Commands:
 *      TOTP                - generate new TOTP
 *          Arguments:  PIN, secret id, current time
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
 *          Arguments:  PIN, secret value, secret name, current time, secret metadata
 *          Returns:    status, secret id
 *
 *      DELETE_SECRET       - delete secret
 *          Arguments:  PIN, secret id
 *          Returns:    status
 *
 *      LIST_SECRET_NAMES   - list names and ids of all secrets
 *          Arguments:  PIN
 *          Returns:    status, amount of secrets, array [{secret id, secret name, secret metadata}]
 *
 *      GET_INFO            - get info about applet
 *          Arguments:
 *          Returns:    status, applet info
 * 
 *      secret values never leaves the card! If you need backup, do it during adding procedure
 */

public class OTPCard extends Applet {

    public interface INS {
        byte TOTP = (byte) 0x00;
        byte SAVE_PIN = (byte) 0x01;
        byte UNBLOCK_PIN = (byte) 0x02;
        byte SAVE_ADMIN_PIN = (byte) 0x03;
        byte SAVE_NEW_SECRET = (byte) 0x04;
        byte DELETE_SECRET = (byte) 0x05;
        byte LIST_SECRET_NAMES = (byte) 0x06;
        byte GET_INFO = (byte) 0x07;
    }

    // Default data
    private static final byte[] PIN_DEFAULT = {'1', '2', '3', '4', '5', '6'};
    private static final byte[] ADMIN_PIN_DEFAULT = {'1', '2', '3', '4', '5', '6', '7', '8'};
    private static final byte MAX_PIN_SIZE = 31;
    private static final byte MIN_PIN_SIZE = 6;

    // Data configured from parameters
    private final byte maxSecrets;
    private final byte maxSecretLength;

    // Persistent data
    private OwnerPIN PIN;
    private OwnerPIN AdminPIN;

    protected OTPCard(byte[] buf, short offData, byte lenData) {
        if (lenData < 2) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        maxSecrets = buf[offData];
        maxSecretLength = buf[(short)(offData + 1)];
        byte PIN_reset_count = buf[(short)(offData + 2)];
        byte AdminPIN_reset_count = buf[(short)(offData + 3)];

        PIN = new OwnerPIN(PIN_reset_count, MAX_PIN_SIZE);
        PIN.update(PIN_DEFAULT, (short)0, (byte)PIN_DEFAULT.length);

        AdminPIN = new OwnerPIN(AdminPIN_reset_count, MAX_PIN_SIZE);
        AdminPIN.update(ADMIN_PIN_DEFAULT, (short)0, (byte)ADMIN_PIN_DEFAULT.length);
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
            case INS.TOTP:
                break;
            case INS.SAVE_PIN:
                updatePin(apdu, PIN);
                break;
            case INS.UNBLOCK_PIN:
                break;
            case INS.SAVE_ADMIN_PIN:
                updatePin(apdu, AdminPIN);
                break;
            case INS.SAVE_NEW_SECRET:
                break;
            case INS.DELETE_SECRET:
                break;
            case INS.LIST_SECRET_NAMES:
                break;
            case INS.GET_INFO:
                getInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void updatePin(APDU apdu, OwnerPIN pin) {
        byte[] buffer = apdu.getBuffer();

        short off_lc = ISO7816.OFFSET_LC;
        if (off_lc >= buffer.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short off_lc_data = (short)(off_lc+1);
        short lc_len = buffer[off_lc];
        if ((short)(off_lc_data + lc_len) >= buffer.length)
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        // Transmitted data is located at ISO7816.OFFSET_LC+1 and has length "lc"
        // Data has form <PIN_LEN> PIN <NEW_PIN_LEN> NEWPIN

        short off_pin_len = 0;
        if (off_pin_len >= lc_len) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return;
        }
        short off_pin = (short)(off_pin_len + 1);
        short pin_len = buffer[(short)(off_lc_data + off_pin_len)];
        if ((short)(off_pin + pin_len) >= lc_len) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return;
        }

        short off_new_pin_len = (short)(off_pin + pin_len);
        if (off_new_pin_len >= lc_len) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return;
        }
        short off_new_pin = (short)(off_new_pin_len + 1);
        short new_pin_len = buffer[(short)(off_lc_data + off_new_pin)];
        if ((short)(off_new_pin + new_pin_len) >= buffer.length) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return;
        }

        // So we have old pin and new pin now
        // Check pin
        if (pin_len > MAX_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        if (new_pin_len > MAX_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        if (new_pin_len < MIN_PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        if (!pin.check(buffer, (short)(off_lc_data + off_pin), (byte)pin_len)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        JCSystem.beginTransaction();
        pin.update(buffer, (short)(off_lc_data + off_new_pin), (byte)new_pin_len);
        JCSystem.commitTransaction();
        pin.resetAndUnblock();
    }

    private void getInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short anslen = 0;

        buffer[anslen++] = maxSecrets;
        buffer[anslen++] = maxSecretLength;
        apdu.setOutgoingAndSend((short) 0, anslen);
    }
}
