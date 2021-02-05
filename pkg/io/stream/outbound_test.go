package stream

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleOutMessage(t *testing.T) {
	addr := ":5701"
	d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

	write := startServer(t, addr)
	target, err := NewStreamOutbound(addr, 5*time.Second)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	assert.NoError(t, err)

	write(d)

	conn := <-ch

	msg := <-conn.Msgs()
	assert.Equal(t, "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", msg.Event.Prefix)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestMultipleOutMessages(t *testing.T) {
	addr := ":5702"
	d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)
	d2 := []byte(`{"v":"KERI10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

	write := startServer(t, addr)
	target, err := NewStreamOutbound(addr, 5*time.Second)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	write(d)
	write(d2)

	conn := <-ch

	msg := <-conn.Msgs()
	assert.Equal(t, "ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY", msg.Event.Prefix)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg", msg.Signatures[0].AsPrefix())

	msg = <-conn.Msgs()
	assert.Equal(t, "E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc", msg.Event.Digest)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestMultipleOutWrites(t *testing.T) {
	addr := ":5703"
	d := []byte(`{"v":"KERI`)
	d2 := []byte(`10JSON000122_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"1","t":"rot","p":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","wt":"0","wr":[],"wa":[],"a":[]}-AABAA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ`)

	write := startServer(t, addr)
	target, err := NewStreamOutbound(addr, 5*time.Second)
	assert.NoError(t, err)

	ch, err := target.Start()
	assert.NoError(t, err)

	write(d)
	write(d2)

	conn := <-ch

	msg := <-conn.Msgs()
	assert.Equal(t, "E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc", msg.Event.Digest)
	assert.Len(t, msg.Signatures, 1)
	assert.Equal(t, "AA91xjNugSykLy0_IZsvkUxkVnZVlNqqhhZT5_VT9wK0pccNrD6i_3h_lTK5ZmXr0wsN6zn-4KMw3ZtYQ2bjbuDQ", msg.Signatures[0].AsPrefix())

	target.Stop()
}

func TestBadOutData(t *testing.T) {
	t.Run("bad version string", func(t *testing.T) {
		addr := ":5704"
		d := []byte(`{"v":"KERL10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		write := startServer(t, addr)
		target, err := NewStreamOutbound(addr, 5*time.Second)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		write(d)
	})
	t.Run("bad format string", func(t *testing.T) {
		addr := ":5705"
		d := []byte(`{"v":"KERI10PROT0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		write := startServer(t, addr)
		target, err := NewStreamOutbound(addr, 5*time.Second)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		write(d)
	})
	t.Run("bad JSON", func(t *testing.T) {
		addr := ":5706"
		d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY},"s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg`)

		write := startServer(t, addr)
		target, err := NewStreamOutbound(addr, 5*time.Second)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		write(d)
	})
	t.Run("bad signature", func(t *testing.T) {
		addr := ":5707"
		d := []byte(`{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-XYZBAA`)

		write := startServer(t, addr)
		target, err := NewStreamOutbound(addr, 5*time.Second)
		assert.NoError(t, err)

		_, err = target.Start()
		assert.NoError(t, err)

		write(d)
	})
}

type msgWriter func(msg []byte)

func startServer(t *testing.T, addr string) msgWriter {
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	ch := make(chan []byte, 2)

	go func() {
		c, err := ln.Accept()
		require.NoError(t, err)

		for msg := range ch {
			_, err = c.Write(msg)
			assert.NoError(t, err)
		}

		c.Close()
	}()

	return func(msg []byte) {
		ch <- msg
	}

}
