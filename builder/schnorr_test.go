package builder_test

import (
	"hide-pay/builder"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.NotEqual(t, fr.Element{}, kp.SecretKey)
	assert.NotEqual(t, fr.Element{}, kp.PublicKey.X)
	assert.NotEqual(t, fr.Element{}, kp.PublicKey.Y)
}

func TestGenerateKeypair_MultipleKeys(t *testing.T) {
	kp1, err := builder.GenerateKeypair()
	require.NoError(t, err)

	kp2, err := builder.GenerateKeypair()
	require.NoError(t, err)

	kp3, err := builder.GenerateKeypair()
	require.NoError(t, err)

	// 所有密钥对应该不同
	assert.NotEqual(t, kp1.SecretKey, kp2.SecretKey)
	assert.NotEqual(t, kp1.SecretKey, kp3.SecretKey)
	assert.NotEqual(t, kp2.SecretKey, kp3.SecretKey)

	assert.NotEqual(t, kp1.PublicKey.X, kp2.PublicKey.X)
	assert.NotEqual(t, kp1.PublicKey.X, kp3.PublicKey.X)
	assert.NotEqual(t, kp2.PublicKey.X, kp3.PublicKey.X)
}

func TestKeypair_Sign(t *testing.T) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)
	assert.NotNil(t, signature)
	assert.NotEqual(t, fr.Element{}, signature.S)
	assert.NotEqual(t, fr.Element{}, signature.R.X)
	assert.NotEqual(t, fr.Element{}, signature.R.Y)
}

func TestKeypair_Sign_MultipleMessages(t *testing.T) {
	random1 := fr.NewElement(12345)
	random2 := fr.NewElement(1234)
	random3 := fr.NewElement(123)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	message1 := fr.NewElement(12345)
	message2 := fr.NewElement(67890)
	message3 := fr.NewElement(11111)

	sig1 := kp.Sign(random1, message1)

	sig2 := kp.Sign(random2, message2)

	sig3 := kp.Sign(random3, message3)

	// 不同消息的签名应该不同
	assert.NotEqual(t, sig1.S, sig2.S)
	assert.NotEqual(t, sig1.S, sig3.S)
	assert.NotEqual(t, sig2.S, sig3.S)

	assert.NotEqual(t, sig1.R.X, sig2.R.X)
	assert.NotEqual(t, sig1.R.X, sig3.R.X)
	assert.NotEqual(t, sig2.R.X, sig3.R.X)
}

func TestKeypair_Sign_SameMessage(t *testing.T) {
	random1 := fr.NewElement(12345)
	random2 := fr.NewElement(1234)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	message := fr.NewElement(12345)

	sig1 := kp.Sign(random1, message)

	sig2 := kp.Sign(random2, message)

	// 相同消息的签名应该不同（因为使用了随机数）
	assert.NotEqual(t, sig1.S, sig2.S)
	assert.NotEqual(t, sig1.R.X, sig2.R.X)
}

func TestVerify_ValidSignature(t *testing.T) {
	privateKey := fr.NewElement(12345)
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypairWithSeed(privateKey)
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)

	// 验证应该成功
	result := builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.True(t, result)
}

func TestVerify_InvalidMessage(t *testing.T) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)

	// 使用不同的消息验证
	wrongMessage := fr.NewElement(67890)
	result := builder.Verify(wrongMessage, signature, &kp.PublicKey)
	assert.False(t, result)
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	random := fr.NewElement(12345)

	kp1, err := builder.GenerateKeypair()
	require.NoError(t, err)

	kp2, err := builder.GenerateKeypair()
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp1.Sign(random, messageHash)

	// 使用错误的公钥验证
	result := builder.Verify(messageHash, signature, &kp2.PublicKey)
	assert.False(t, result)
}

func TestVerify_InvalidSignature(t *testing.T) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)

	// 修改签名
	originalS := signature.S
	signature.S = fr.NewElement(99999)

	result := builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.False(t, result)

	// 恢复原始签名
	signature.S = originalS
	result = builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.True(t, result)
}

func TestVerify_ZeroMessage(t *testing.T) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	messageHash := fr.NewElement(0)
	signature := kp.Sign(random, messageHash)

	result := builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.True(t, result)
}

func TestVerify_LargeMessage(t *testing.T) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	// 使用一个较大的消息
	messageHash := fr.NewElement(0xFFFFFFFFFFFFFFFF)
	signature := kp.Sign(random, messageHash)

	result := builder.Verify(messageHash, signature, &kp.PublicKey)
	assert.True(t, result)
}

func TestSignVerify_MultipleKeypairs(t *testing.T) {
	// 测试多个密钥对的签名和验证
	keypairs := make([]*builder.Keypair, 5)
	for i := range keypairs {
		kp, err := builder.GenerateKeypair()
		require.NoError(t, err)
		keypairs[i] = kp
	}

	message := fr.NewElement(12345)
	random := fr.NewElement(12345)

	for i, kp := range keypairs {
		signature := kp.Sign(random, message)

		// 使用正确的公钥验证应该成功
		result := builder.Verify(message, signature, &kp.PublicKey)
		assert.True(t, result, "Verification failed for keypair %d", i)

		// 使用错误的公钥验证应该失败
		for j, otherKp := range keypairs {
			if i != j {
				result := builder.Verify(message, signature, &otherKp.PublicKey)
				assert.False(t, result, "Verification should fail with wrong public key %d", j)
			}
		}
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	random1 := fr.NewElement(12345)
	random2 := fr.NewElement(12345)

	// 测试哈希函数的确定性
	message := fr.NewElement(12345)

	// 创建密钥对
	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	// 使用相同的输入计算哈希 - 通过签名来间接测试哈希函数
	sig1 := kp.Sign(random1, message)
	sig2 := kp.Sign(random2, message)

	// 虽然签名会不同（因为随机数），但验证应该都成功
	result1 := builder.Verify(message, sig1, &kp.PublicKey)
	result2 := builder.Verify(message, sig2, &kp.PublicKey)

	assert.True(t, result1)
	assert.True(t, result2)
}

func TestComputeHash_DifferentInputs(t *testing.T) {
	random1 := fr.NewElement(12345)
	random2 := fr.NewElement(1234)

	// 测试不同输入产生不同的哈希
	message1 := fr.NewElement(12345)
	message2 := fr.NewElement(67890)

	kp, err := builder.GenerateKeypair()
	require.NoError(t, err)

	// 不同消息的签名应该不同
	sig1 := kp.Sign(random1, message1)
	sig2 := kp.Sign(random2, message2)

	assert.NotEqual(t, sig1.S, sig2.S)
	assert.NotEqual(t, sig1.R.X, sig2.R.X)
}

// 基准测试
func BenchmarkGenerateKeypair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := builder.GenerateKeypair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	messageHash := fr.NewElement(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp.Sign(random, messageHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	random := fr.NewElement(12345)

	kp, err := builder.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	messageHash := fr.NewElement(12345)
	signature := kp.Sign(random, messageHash)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := builder.Verify(messageHash, signature, &kp.PublicKey)
		if !result {
			b.Fatal("Verification failed")
		}
	}
}
