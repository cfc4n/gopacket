package pcapgo

type decryptionSecret struct {
	blockInfo pcapngDecryptionSecretsBlock
	payload   []byte
}

// readDecryptionSecrets parses an encryption secrets section from the given
func (r *NgReader) readDecryptionSecrets() error {
	if err := r.readBytes(r.buf[:8]); err != nil {
		return err
	}
	r.currentBlock.length -= 8
	var blockHeader *pcapngBlockHeader
	blockHeader.blockType = r.getUint32(r.buf[:4])
	blockHeader.blockTotalLength = r.getUint32(r.buf[4:8])

	if err := r.readBytes(r.buf[8:16]); err != nil {
		return err
	}
	r.currentBlock.length -= 8
	var decryptionSecretsBlock *pcapngDecryptionSecretsBlock
	decryptionSecretsBlock.secretsType = r.getUint32(r.buf[8:12])
	decryptionSecretsBlock.secretsLength = r.getUint32(r.buf[12:16])

	var payload = make([]byte, decryptionSecretsBlock.secretsLength)
	if err := r.readBytes(payload); err != nil {
		return err
	}
	r.currentBlock.length -= uint32(len(payload))

	// save decryption secrets
	var decryptSecret decryptionSecret
	decryptSecret.blockInfo = *decryptionSecretsBlock
	decryptSecret.payload = payload
	r.decryptionSecrets = append(r.decryptionSecrets, decryptSecret)
	return nil
}
