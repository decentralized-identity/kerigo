package stream

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSingleMessage(t *testing.T) {
	addr := ":5601"
	d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

	target, err := NewStreamInbound(addr)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	sendMsg(t, addr, d)

	msg := <-ch
	assert.Equal(t, "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", msg.Event.Prefix)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestMultipleMessages(t *testing.T) {
	addr := ":5602"
	d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)
	d2 := []byte(`{"v":"KERI10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

	target, err := NewStreamInbound(addr)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	sendMsg(t, addr, d, d2)

	msg := <-ch
	assert.Equal(t, "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", msg.Event.Prefix)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg", msg.Signatures[0].AsPrefix())

	msg = <-ch
	assert.Equal(t, "E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc", msg.Event.Digest)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestMultipleWrites(t *testing.T) {
	addr := ":5603"
	d := []byte(`{"v":"KERI`)
	d2 := []byte(`10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

	target, err := NewStreamInbound(addr)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	sendMsg(t, addr, d, d2)

	msg := <-ch
	assert.Equal(t, "E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc", msg.Event.Digest)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestBadData(t *testing.T) {
	t.Run("bad version string", func(t *testing.T) {
		addr := ":5604"
		d := []byte(`{"v":"KERL10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		target, err := NewStreamInbound(addr)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		sendMsg(t, addr, d)
	})
	t.Run("bad format string", func(t *testing.T) {
		addr := ":5605"
		d := []byte(`{"v":"KERI10PROT0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		target, err := NewStreamInbound(addr)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		sendMsg(t, addr, d)
	})
	t.Run("bad JSON", func(t *testing.T) {
		addr := ":5606"
		d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY},"s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		target, err := NewStreamInbound(addr)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		sendMsg(t, addr, d)
	})
	t.Run("bad signature", func(t *testing.T) {
		addr := ":5607"
		d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-XYZBAA`)

		target, err := NewStreamInbound(addr)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		sendMsg(t, addr, d)
	})
}

func sendMsg(t *testing.T, addr string, msgs ...[]byte) {
	client, err := net.Dial("tcp", addr)
	assert.NoError(t, err)

	for _, msg := range msgs {
		_, err = client.Write(msg)
		assert.NoError(t, err)
	}

	err = client.Close()
	assert.NoError(t, err)
}
