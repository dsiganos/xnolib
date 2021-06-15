# This is by no means finished and will be updated! 

meta: 
    id: parsing
    title: this is the parser for the bulk pull response.

types:
    block_send:
        seq:
            - id: previous
              size: 32
            - id: destination
              size: 32
            - id: balance
              size: 16
            - id: signature
              size: 64
            - id: work
              type: u8le 

    block_receive:
        seq:
            - id: previous
              size: 32
            - id: source
              size: 32
            - id: signature
              size: 32
            - id: work
              type: u8le
                
    block_open:
        seq:
            - id: source
              size: 32
            - id: representative
              size: 32 
            - id: account 
              size: 32
            - id: signature
              size: 64
            - id: work 
              type: u8le
    
    block_change:
        seq:
            - id: previous
              size: 32
            - id: representative
              size: 32 
            - id: signature
              size: 64
            - id: work
              type: u8le
    
    block_state: 
        seq:
            - id: account
              size: 32
            - id: previous
              size: 32
            - id: representative
              size: 32
            - id: balance
              size: 16
            - id: link
              size: 32
            - id: signature
              size: 64
            - id: work
              type: u8be
    
    bulk_pull_response:
        seq:
            - id: bulk_pull_entry
              type: bulk_pull_entry

        types:
            bulk_pull_entry:
                seq:
                    - id: block_type
                      type: u1
                    - id: send
                      type: block_send
                      if: block_type == 2
                    - id: receive
                      type: block_receive
                      if: block_type == 3
                    - id: open 
                      type: block_open 
                      if: block_type == 4
                    - id: change
                      type: block_change
                      if: block_type == 5
                    - id: state
                      type: block_state
                      if: block_type == 6
