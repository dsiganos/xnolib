
# This is by no means finished and will be updated! 


meta: 
    id: not_sure_what_to_put_here
    endian: le
types:
    bulk_pull_response:
        seq:
            - id: bulk_pull_entry
              type: bulk_pull_entry

        types:
            bulk_pull_entry:
                seq:
                    - id: block_type
                      type: u1
                    - id: block
                      type: block_selector(block_type)
    
    block_selector:
        params:
          - id: block_type_arg
            type: u1
        seq:
            - id: block 
              type:
                switch-on: block_type_arg
                cases:
                    'enum_block_type::send.to_i' : block_send
                    'enum_block_type::receive.to_i' : block_receive
                    'enum_block_type::open.to_i' : block_open
                    'enum_block_type::change.to_i' : block_change
                    'enum_block_type::state.to_i' : block_state
    block_send:
        seq:
            - id: previous
              type: 32be
            - id: destination
              size: 32
            - id: balance
              size: 16 

                

        
        

enums:
    enum_block_type: 
        0x0: invalid
        0x1: not_a_block
        0x2: send
        0x3: receive
        0x4: open
        0x5: change
        0x6: state
