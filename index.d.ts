/// <reference path="./typings/index.d.ts" />

declare module "jsonwebtoken" {

    export type Algorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512' | 'none';

    export interface SignOptions {

        algorithm?: Algorithm;
        expiresIn?: Number | String;
        notBefore?: Number | String;
        audience?: String;
        issuer?: String;
        jwtid?: String;
        subject?: String;
        noTimestamp?: Boolean;
        header?: Object;
    }

    export type SignCallback = (err: any, token: String) => void;

    export interface VerifyOptions {

        algorithms?: Algorithm[];
        audience?: String;
        issuser?: String;
        ignoreExpiration?: Boolean;
        subject?: String;
        clockTolerance?: Number;
        maxAge?: Number | String;
        clockTimestamp?: Number;
    }

    export type VerifyCallback = (err: any, payload: Object | Buffer | String) => void;

    export interface DecodeOptions {

        json?: Boolean;
        complete?: Object;
    }

    /**
     * Generate a JSON Web Token string based on the given payload and options and proceed with the callback function
     * @param {Object|Buffer|String} payload - Object literal, buffer or string. Please note that exp is only set if the payload is an object literal
     * @param {Buffer|String} secretOrPrivateKey - String or buffer containing either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA
     * @param {SignOptions} options
     * @param {SignCallback} callback - The function to be called after the JSON Web Token string is generated
     */
    export function sign(payload: Object | Buffer | String, secretOrPrivateKey: Buffer | String, options?: SignOptions, callback?: SignCallback): String | void;

    /**
     * Verify a JSON Web Token string based on the given options and proceed with the callback function if provided
     * @param {String} token - JSON Web Token string
     * @param {Buffer|String} secretOrPublicKey - String or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
     * @param {VerifyOptions} options
     * @param {VerifyCallback} callback - The function to be called after verification is complete
     */
    export function verify(token: String, secretOrPublicKey: Buffer | String, options?: VerifyOptions, callback?: VerifyCallback): Object | Buffer | String | void;

    /**
     * Decode a JSON Web Token string without verifying its signature
     * @param {String} token - The JSON Web Token String
     * @param {DecodeOptions} options
     */
    export function decode(token: String, options?: DecodeOptions): Object | Buffer | String;
}